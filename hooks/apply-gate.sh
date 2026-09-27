#!/usr/bin/env bash
# whatbreaks apply gate — PreToolUse hook for the Bash tool.
#
# Denies `terraform|tofu|terragrunt apply` and `destroy` unless the exact plan file
# being applied has a review marker written by /whatbreaks:review (or an approval
# written by /whatbreaks:approve when the review verdict was BLOCK).
#
# What it reads: the hook's JSON on stdin (tool_input.command, cwd), the plan file
# named in the command (to hash it), and marker files under
# ${CLAUDE_PLUGIN_DATA}/reviews. What it writes: a JSON decision on stdout. It never
# runs terraform, never modifies files, and never touches the network.
#
# Disable with the plugin's `apply_gate` option (userConfig) — never by editing this file.
#
# Compatible with bash 3.2 (macOS). Uses jq or python3 for JSON when present and a
# sed fallback otherwise.

set -u

# ---------------------------------------------------------------- helpers
deny() {
  # $1 = reason. Newlines are written as @NL@ in messages. The reason is JSON-escaped so that
  # user-controlled text (a plan file name) can never produce invalid JSON, and the script
  # exits 2, which blocks the tool call even if the JSON were somehow unreadable.
  local reason
  reason=$(printf '%s' "$1" | tr -d '\000-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/@NL@/\\n/g')
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$reason"
  printf '%s\n' "$1" | sed 's/@NL@/ /g' >&2
  exit 2
}
allow() { exit 0; }

json_field() {
  # $1 = jq path (e.g. .tool_input.command), $2 = python expression on obj, $3 = key name for sed fallback
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$INPUT" | jq -r "$1 // empty" 2>/dev/null
  elif command -v python3 >/dev/null 2>&1; then
    printf '%s' "$INPUT" | python3 -c 'import json,sys
try:
    o=json.load(sys.stdin)
    v='"$2"'
    sys.stdout.write("" if v is None else str(v))
except Exception:
    pass' 2>/dev/null
  else
    # crude: first "key":"value" occurrence, unescaping \" \\ \n
    printf '%s' "$INPUT" | tr '\n' ' ' | sed -n 's/.*"'"$3"'"[[:space:]]*:[[:space:]]*"\(\([^"\\]\|\\.\)*\)".*/\1/p' \
      | sed -e 's/\\"/"/g' -e 's/\\n/ /g' -e 's/\\\\/\\/g'
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$1" | awk '{print $NF}'
  else echo ""; fi
}

marker_field() {
  # $1 = marker file, $2 = key -> prints value (lowercase) or empty
  if command -v jq >/dev/null 2>&1; then
    jq -r ".$2 // empty" "$1" 2>/dev/null | tr 'A-Z' 'a-z'
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys
try:
    print(str(json.load(open(sys.argv[1])).get(sys.argv[2],"")).lower())
except Exception:
    pass' "$1" "$2" 2>/dev/null
  else
    sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\{0,1\}\([A-Za-z0-9_-]*\)"\{0,1\}.*/\1/p' "$1" | head -1 | tr 'A-Z' 'a-z'
  fi
}

# ---------------------------------------------------------------- input
INPUT=$(cat)
CMD=$(json_field '.tool_input.command' 'o.get("tool_input",{}).get("command")' 'command')
[ -z "$CMD" ] && allow

# Fast path: nothing terraform-like in the command.
case "$CMD" in
  *terraform*|*tofu*|*terragrunt*) ;;
  *) allow ;;
esac

# User switched the gate off via userConfig (CLAUDE_PLUGIN_OPTION_<KEY>).
GATE="${CLAUDE_PLUGIN_OPTION_APPLY_GATE:-${CLAUDE_PLUGIN_OPTION_apply_gate:-true}}"
case "$(printf '%s' "$GATE" | tr 'A-Z' 'a-z')" in
  false|0|no|off) allow ;;
esac

CWD=$(json_field '.cwd' 'o.get("cwd")' 'cwd')
[ -z "$CWD" ] && CWD=$(pwd)
MARKER_DIR="${CLAUDE_PLUGIN_DATA:-$HOME/.claude/plugins/data/whatbreaks}/reviews"

HOWTO='Run the plan and review it first:@NL@  terraform plan -out=tfplan@NL@  /whatbreaks:review tfplan@NL@then apply that exact file: terraform apply tfplan. (If the review verdict is BLOCK, the user must explicitly accept the risk via /whatbreaks:approve tfplan.)'

# Env-var back doors that auto-approve or inject flags: treat like -auto-approve.
case "$CMD" in
  *TF_CLI_ARGS*|*TG_NON_INTERACTIVE*|*TERRAGRUNT_NON_INTERACTIVE*|*TF_INPUT=*)
    ENV_ARGS=1 ;;
  *) ENV_ARGS=0 ;;
esac

# ---------------------------------------------------------------- split into simple commands
SEGS=${CMD//'||'/$'\n'}
SEGS=${SEGS//'&&'/$'\n'}
SEGS=${SEGS//';'/$'\n'}
SEGS=${SEGS//'|'/$'\n'@PIPE@ }
SEGS=${SEGS//'&'/$'\n'}
SEGS=${SEGS//'$('/$'\n'}
SEGS=${SEGS//'`'/$'\n'}

EFFECTIVE_CWD="$CWD"
SAW_PLAN_SUBCMD=0

while IFS= read -r SEG; do
  PIPED=0
  case "$SEG" in
    @PIPE@*) PIPED=1; SEG=${SEG#@PIPE@} ;;
  esac
  REDIRECT_IN=0
  case "$SEG" in *'<'*) REDIRECT_IN=1 ;; esac

  # shellcheck disable=SC2206
  read -r -a W <<< "$SEG" || true
  [ "${#W[@]}" -eq 0 ] && continue

  # Strip leading env assignments and wrappers.
  i=0
  while [ $i -lt "${#W[@]}" ]; do
    t="${W[$i]}"
    case "$t" in
      [A-Za-z_]*=*) i=$((i+1)); continue ;;
      sudo|env|time|nohup|command|exec|nice|ionice|stdbuf|unbuffer|caffeinate|doas)
        i=$((i+1))
        while [ $i -lt "${#W[@]}" ] && case "${W[$i]}" in -*) true;; *) false;; esac; do i=$((i+1)); done
        continue ;;
      timeout) i=$((i+2)); continue ;;
      cd)
        if [ $((i+1)) -lt "${#W[@]}" ]; then
          d="${W[$((i+1))]}"; d=${d%\"}; d=${d#\"}; d=${d%\'}; d=${d#\'}
          case "$d" in /*) EFFECTIVE_CWD="$d" ;; "~"*) EFFECTIVE_CWD="$HOME${d#\~}" ;; *) EFFECTIVE_CWD="$EFFECTIVE_CWD/$d" ;; esac
        fi
        continue 2 ;;
    esac
    break
  done
  [ $i -ge "${#W[@]}" ] && continue
  BIN="${W[$i]}"; BIN=${BIN##*/}; BIN=${BIN%.exe}
  case "$BIN" in terraform|tofu|terragrunt) ;; *) continue ;; esac
  i=$((i+1))

  CHDIR=""
  SUB=""
  RUNALL=0
  # global flags, then subcommand
  while [ $i -lt "${#W[@]}" ]; do
    t="${W[$i]}"
    case "$t" in
      -chdir=*) CHDIR=${t#-chdir=} ; i=$((i+1)) ;;
      --all) RUNALL=1; i=$((i+1)) ;;
      -*) i=$((i+1)) ;;
      run-all) RUNALL=1; i=$((i+1)) ;;
      run) i=$((i+1)) ;;
      *) SUB="$t"; i=$((i+1)); break ;;
    esac
  done
  [ "$SUB" = "plan" ] && SAW_PLAN_SUBCMD=1
  case "$SUB" in apply|destroy) ;; *) continue ;; esac

  DESTROY=0; AUTO=0; PLANFILE=""
  [ "$SUB" = "destroy" ] && DESTROY=1
  while [ $i -lt "${#W[@]}" ]; do
    t="${W[$i]}"
    case "$t" in
      --) i=$((i+1)); if [ $i -lt "${#W[@]}" ] && [ -z "$PLANFILE" ]; then PLANFILE="${W[$i]}"; fi; break ;;
      -destroy|--destroy) DESTROY=1; i=$((i+1)) ;;
      -auto-approve|--auto-approve|-auto-approve=true|--auto-approve=true) AUTO=1; i=$((i+1)) ;;
      --terragrunt-non-interactive|--non-interactive) AUTO=1; i=$((i+1)) ;;
      -var|-var-file|-target|-replace|-exclude|-parallelism|-backup|-state|-state-out|-lock-timeout|\
      --terragrunt-working-dir|--working-dir|--terragrunt-config|--config|--terragrunt-iam-role|--iam-role|\
      --terragrunt-include-dir|--queue-include-dir|--terragrunt-exclude-dir|--queue-exclude-dir|\
      --terragrunt-download-dir|--download-dir|--terragrunt-parallelism|--terragrunt-log-level|--log-level|\
      --terragrunt-source|--source|--terragrunt-source-map|--terragrunt-strict-control|--strict-control)
        i=$((i+2)) ;;
      -*) i=$((i+1)) ;;
      *) [ -z "$PLANFILE" ] && PLANFILE="$t"; i=$((i+1)) ;;
    esac
  done
  PLANFILE=${PLANFILE%\"}; PLANFILE=${PLANFILE#\"}; PLANFILE=${PLANFILE%\'}; PLANFILE=${PLANFILE#\'}

  # ---- decisions ----
  if [ "$RUNALL" -eq 1 ]; then
    deny "whatbreaks: terragrunt run-all $SUB applies every module at once with no per-module plan review. Run plan per module with -out, review each with /whatbreaks:review, then apply the reviewed plan files."
  fi

  if [ -z "$PLANFILE" ]; then
    if [ "$DESTROY" -eq 1 ]; then
      deny "whatbreaks: $BIN destroy is blocked. Create a destroy plan instead:@NL@  $BIN plan -destroy -out=destroy.tfplan@NL@  /whatbreaks:review destroy.tfplan@NL@The review verdict will be BLOCK (everything is destroyed), so the user must explicitly approve it with /whatbreaks:approve destroy.tfplan before $BIN apply destroy.tfplan is allowed."
    fi
    if [ "$AUTO" -eq 1 ] || [ "$ENV_ARGS" -eq 1 ] || [ "$PIPED" -eq 1 ] || [ "$REDIRECT_IN" -eq 1 ]; then
      deny "whatbreaks: $BIN apply with -auto-approve (or piped/env-injected approval) but no saved plan file would apply whatever the current plan is, unreviewed. $HOWTO"
    fi
    deny "whatbreaks: $BIN apply without a saved plan file cannot be reviewed before it runs. $HOWTO"
  fi

  # Resolve the plan file: relative to the effective cwd, else to -chdir.
  RESOLVED=""
  for base in "$EFFECTIVE_CWD" "${CHDIR:+$EFFECTIVE_CWD/$CHDIR}"; do
    [ -z "$base" ] && continue
    case "$PLANFILE" in /*) cand="$PLANFILE" ;; *) cand="$base/$PLANFILE" ;; esac
    if [ -f "$cand" ]; then RESOLVED="$cand"; break; fi
  done
  if [ -z "$RESOLVED" ]; then
    if [ "$SAW_PLAN_SUBCMD" -eq 1 ]; then
      deny "whatbreaks: this command creates the plan and applies it in one step, so nothing is reviewed in between. Run the plan first, then /whatbreaks:review $PLANFILE, then apply."
    fi
    deny "whatbreaks: plan file $PLANFILE was not found (looked in $EFFECTIVE_CWD), so it cannot have been reviewed. $HOWTO"
  fi

  HASH=$(sha256_of "$RESOLVED")
  [ -z "$HASH" ] && deny "whatbreaks: cannot hash $PLANFILE (no sha256sum/shasum/openssl on PATH), so the review cannot be verified. $HOWTO"
  MARKER="$MARKER_DIR/$HASH.json"
  if [ ! -f "$MARKER" ]; then
    deny "whatbreaks: $PLANFILE has not been reviewed (no review marker for sha256 ${HASH:0:12}). Run /whatbreaks:review $PLANFILE first. Note: re-running plan produces a new file that needs its own review."
  fi
  APPROVED=$(marker_field "$MARKER" approved)
  VERDICT=$(marker_field "$MARKER" verdict)
  STATUS=$(marker_field "$MARKER" status)
  if [ "$APPROVED" = "true" ]; then
    allow
  fi
  if [ "$VERDICT" = "block" ] || [ "$STATUS" = "blocked" ]; then
    deny "whatbreaks: the review of $PLANFILE ended in BLOCK (critical findings). Applying needs the user's explicit acceptance: after they confirm, run /whatbreaks:approve $PLANFILE, then apply."
  fi
  if [ "$STATUS" = "reviewed" ] || [ "$STATUS" = "approved" ]; then
    allow
  fi
  deny "whatbreaks: the review marker for $PLANFILE is incomplete (status=$STATUS verdict=$VERDICT). Re-run /whatbreaks:review $PLANFILE."
done <<EOF
$SEGS
EOF

allow
