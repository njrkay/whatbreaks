#!/usr/bin/env bash
# whatbreaks apply gate — PreToolUse hook for the Bash tool.
#
# Denies `terraform|tofu|terragrunt apply` and `destroy` unless the exact plan file being
# applied has a review marker written by /whatbreaks:review (or an approval written by
# /whatbreaks:approve when the review verdict was BLOCK).
#
# What it reads: the hook's JSON on stdin (tool_input.command, cwd), the plan file named in
# the command (to hash it), and marker files under ${CLAUDE_PLUGIN_DATA}/reviews. What it
# writes: a JSON decision on stdout. It never runs terraform, never modifies files, and
# never touches the network.
#
# Design rules:
#   * Fail closed. Any internal error, unparsable input that mentions terraform, or an
#     over-long command that mentions apply/destroy is a deny (exit 2), never an allow.
#   * Never exit 0 from inside the per-command loop: a reviewed apply followed by an
#     unreviewed one in the same line must still be denied.
#   * The hash is only trusted when nothing earlier in the same command line could have
#     (re)written the plan file.
#
# Disable with the plugin's `apply_gate` option (userConfig) — never by editing this file.
# Compatible with bash 3.2 (macOS). Uses jq or python3 for JSON when present and a
# BSD-sed-safe fallback otherwise.

set -u

# ---------------------------------------------------------------- output helpers
deny() {
  # $1 = reason. Newlines are written as @NL@. The reason is JSON-escaped so that
  # user-controlled text (a plan file name) can never produce invalid JSON, and the
  # script exits 2, which blocks the tool call even if the JSON were unreadable.
  local reason
  reason=$(printf '%s' "$1" | tr -d '\000-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/@NL@/\\n/g')
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$reason"
  printf '%s\n' "$1" | sed 's/@NL@/ /g' >&2
  exit 2
}
allow() { exit 0; }

json_field() {
  # $1 = jq path, $2 = python expression on obj, $3 = key name for the sed fallback
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
    # BSD-safe regex (no GNU \| alternation); JSON \n becomes ";" so the splitter still
    # sees separate commands.
    printf '%s' "$INPUT" | tr '\n' ' ' | sed -n 's/.*"'"$3"'"[[:space:]]*:[[:space:]]*"\([^"]*\(\\"[^"]*\)*\)".*/\1/p' \
      | sed -e 's/\\"/"/g' -e 's/\\n/;/g' -e 's/\\t/ /g' -e 's/\\\\/\\/g'
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$1" | awk '{print $NF}'
  else echo ""; fi
}

marker_field() {
  # $1 = marker file, $2 = key -> prints the value lowercased, or nothing
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

unquote() {
  # Strip shell quoting from one token for matching purposes (expands nothing).
  printf '%s' "$1" | sed -e "s/^\\\$'//" -e 's/["'"'"'\\]//g'
}

is_tf_binary() {
  local b="$1"; b=${b##*/}; b=${b%.exe}
  case "$b" in terraform|tofu|opentofu|terragrunt|terraform-*|terraform_*|tofu-*|tofu_*) return 0 ;; esac
  return 1
}

# ---------------------------------------------------------------- input
INPUT=$(cat)
CMD=$(json_field '.tool_input.command' 'o.get("tool_input",{}).get("command")' 'command')

# Fail closed if the payload looks terraform-ish but could not be parsed.
if [ -z "$CMD" ]; then
  case "$INPUT" in
    *terraform*|*tofu*|*terragrunt*)
      case "$INPUT" in
        *apply*|*destroy*) deny "whatbreaks: could not parse the hook input (no jq or python3?), so refusing to gate blindly. Install jq or python3, or turn the gate off with the apply_gate option." ;;
      esac ;;
  esac
  allow
fi

# Fast path: nothing terraform-like in the command.
case "$CMD" in
  *terraform*|*tofu*|*terragrunt*) ;;
  *) allow ;;
esac

# A huge command could push the tokenizer past the hook timeout, and a timed-out hook does
# not block. Refuse to gate it.
if [ "${#CMD}" -gt 131072 ]; then
  case "$CMD" in *apply*|*destroy*) deny "whatbreaks: command is too long (${#CMD} bytes) to gate safely; split it up." ;; esac
fi

# From here on any unexpected error must deny (exit 1 would be treated as non-blocking).
trap 'rc=$?; if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then printf "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"whatbreaks: hook failed internally (exit %s); refusing to allow a terraform command blindly.\"}}\n" "$rc"; exit 2; fi' EXIT

# User switched the gate off via userConfig (CLAUDE_PLUGIN_OPTION_<KEY>).
GATE="${CLAUDE_PLUGIN_OPTION_APPLY_GATE:-${CLAUDE_PLUGIN_OPTION_apply_gate:-true}}"
case "$(printf '%s' "$GATE" | tr 'A-Z' 'a-z')" in
  false|0|no|off) allow ;;
esac

CWD=$(json_field '.cwd' 'o.get("cwd")' 'cwd')
[ -z "$CWD" ] && CWD=$(pwd)
HOME="${HOME:-/nonexistent}"
if [ -n "${CLAUDE_PLUGIN_DATA:-}" ]; then
  MARKER_DIR="$CLAUDE_PLUGIN_DATA/reviews"
else
  MARKER_DIR=""
fi

# Env-var back doors that auto-approve or inject flags: treated like -auto-approve.
case "$CMD" in
  *TF_CLI_ARGS*|*TG_NON_INTERACTIVE*|*TERRAGRUNT_NON_INTERACTIVE*|*TF_INPUT=*) ENV_ARGS=1 ;;
  *) ENV_ARGS=0 ;;
esac

# ---------------------------------------------------------------- split into simple commands
CMD=${CMD//$'\\\n'/ }            # join backslash-newline continuations first
SEGS=${CMD//'||'/$'\n'}
SEGS=${SEGS//'&&'/$'\n'}
SEGS=${SEGS//';'/$'\n'}
SEGS=${SEGS//'|'/$'\n'@PIPE@ }
SEGS=${SEGS//'&'/$'\n'}
SEGS=${SEGS//'$('/$'\n'}
SEGS=${SEGS//'`'/$'\n'}
SEGS=${SEGS//'('/$'\n'}          # subshell
SEGS=${SEGS//'{'/$'\n'}          # group

EFFECTIVE_CWD="$CWD"
SAW_PLAN_SUBCMD=0   # an earlier command in this line ran `plan` (may have written the file)
SAW_WRITER=0        # an earlier command in this line can (re)write files
PREV_SEG=""         # previous simple command, for `echo terraform apply x | bash`
HEREDOC_END=""      # inside a here-document body until this terminator line

while IFS= read -r SEG; do
  # Skip here-document bodies: they are data, not commands.
  if [ -n "$HEREDOC_END" ]; then
    trimmed=$(printf '%s' "$SEG" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    [ "$trimmed" = "$HEREDOC_END" ] && HEREDOC_END=""
    continue
  fi
  case "$SEG" in
    *'<<'*)
      case "$SEG" in *'<<<'*) ;; *)
        hd=$(printf '%s' "$SEG" | sed -n 's/.*<<-\{0,1\}[[:space:]]*["'"'"']\{0,1\}\([A-Za-z_][A-Za-z0-9_]*\).*/\1/p' | head -1)
        [ -n "$hd" ] && HEREDOC_END="$hd" ;;
      esac ;;
  esac

  PIPED=0
  case "$SEG" in @PIPE@*) PIPED=1; SEG=${SEG#@PIPE@} ;; esac
  REDIRECT_IN=0
  case "$SEG" in *'<'*) REDIRECT_IN=1 ;; esac
  SEG_WRITES=0
  case "$SEG" in *'>'*) SEG_WRITES=1 ;; esac

  # Tokenize with quote awareness when python3 is present; otherwise whitespace + unquote.
  W=()
  if command -v python3 >/dev/null 2>&1; then
    while IFS= read -r tok; do W+=("$tok"); done < <(printf '%s' "$SEG" | python3 -c 'import shlex,sys
s=sys.stdin.read()
try:
    toks=shlex.split(s, comments=True, posix=True)
except ValueError:
    toks=s.split()
for t in toks:
    print(t[:4096])' 2>/dev/null)
  else
    read -r -a RAW <<< "$SEG" || true
    for tok in "${RAW[@]+"${RAW[@]}"}"; do W+=("$(unquote "${tok:0:4096}")"); done
  fi
  if [ "${#W[@]}" -eq 0 ]; then PREV_SEG="$SEG"; continue; fi

  # `echo terraform apply x | bash`: a shell reading its script from a pipe.
  if [ "$PIPED" -eq 1 ]; then
    case "${W[0]}" in
      bash|sh|zsh|dash|ksh)
        has_c=0
        for tok in "${W[@]+"${W[@]}"}"; do case "$tok" in -c|-*c*) has_c=1 ;; esac; done
        if [ "$has_c" -eq 0 ]; then
          case "$PREV_SEG" in
            *terraform*|*tofu*|*terragrunt*)
              case "$PREV_SEG" in *apply*|*destroy*)
                deny "whatbreaks: a terraform apply/destroy piped into a shell cannot be reviewed. Run the plan, review it with /whatbreaks:review, then apply the reviewed plan file directly." ;;
              esac ;;
          esac
        fi ;;
    esac
  fi

  i=0
  while [ $i -lt "${#W[@]}" ]; do
    t="${W[$i]}"
    case "$t" in
      then|do|else|elif|'!'|if|while|until) i=$((i+1)); continue ;;
      [A-Za-z_]*=*) i=$((i+1)); continue ;;
      --) i=$((i+1)); continue ;;
      sudo|env|time|nohup|command|exec|nice|ionice|stdbuf|unbuffer|caffeinate|doas|flock|chronic|ts|strace|ltrace|watch|timeout|\
      aws-vault|op|direnv|mise|asdf|tfenv|tgenv|poetry|pipenv|bundle|docker|podman|nix-shell|nix|devbox|just|task)
        # Generic wrapper: skip it, its options and their values, up to the first token that is
        # a terraform binary (position-independent, so `aws-vault exec prod -- terraform` works).
        j=$((i+1)); found=-1
        while [ $j -lt "${#W[@]}" ]; do
          if is_tf_binary "${W[$j]}"; then found=$j; break; fi
          j=$((j+1))
        done
        if [ $found -ge 0 ]; then i=$found; else i=${#W[@]}; fi
        break ;;
      bash|sh|zsh|dash|ksh|eval|xargs|find|script|expect|ssh)
        # Shells/evaluators receive a command string: re-split every remaining token on
        # whitespace (a quoted "terraform apply x" becomes three words) and scan forward.
        NEWW=()
        j=$((i+1))
        while [ $j -lt "${#W[@]}" ]; do
          read -r -a PARTS <<< "${W[$j]}" || true
          for q in "${PARTS[@]+"${PARTS[@]}"}"; do NEWW+=("$q"); done
          j=$((j+1))
        done
        W=("${NEWW[@]+"${NEWW[@]}"}")
        j=0; found=-1
        while [ $j -lt "${#W[@]}" ]; do
          if is_tf_binary "${W[$j]}"; then found=$j; break; fi
          j=$((j+1))
        done
        if [ $found -ge 0 ]; then i=$found; else i=${#W[@]}; fi
        break ;;
      cd|pushd)
        if [ $((i+1)) -lt "${#W[@]}" ]; then
          d="${W[$((i+1))]}"
          case "$d" in /*) EFFECTIVE_CWD="$d" ;; "~"*) EFFECTIVE_CWD="$HOME${d#\~}" ;; *) EFFECTIVE_CWD="$EFFECTIVE_CWD/$d" ;; esac
        fi
        PREV_SEG="$SEG"; continue 2 ;;
      cp|mv|ln|curl|wget|tee|dd|install|rsync|touch|truncate)
        SAW_WRITER=1; PREV_SEG="$SEG"; continue 2 ;;
    esac
    break
  done
  if [ $i -ge "${#W[@]}" ]; then
    [ "$SEG_WRITES" -eq 1 ] && SAW_WRITER=1
    PREV_SEG="$SEG"; continue
  fi
  BIN="${W[$i]}"
  if ! is_tf_binary "$BIN"; then
    [ "$SEG_WRITES" -eq 1 ] && SAW_WRITER=1
    PREV_SEG="$SEG"; continue
  fi
  BIN=${BIN##*/}; BIN=${BIN%.exe}
  i=$((i+1))

  CHDIR=""; SUB=""; RUNALL=0
  while [ $i -lt "${#W[@]}" ]; do
    t="${W[$i]}"
    case "$t" in
      -chdir=*) CHDIR=${t#-chdir=} ; i=$((i+1)) ;;
      --all) RUNALL=1; i=$((i+1)) ;;
      -*) i=$((i+1)) ;;
      run-all) RUNALL=1; i=$((i+1)) ;;
      run|stack|exec) i=$((i+1)) ;;
      *)
        if is_tf_binary "$t"; then
          # e.g. `terragrunt exec -- terraform apply`: restart at the nested binary
          BIN=${t##*/}; BIN=${BIN%.exe}; i=$((i+1)); continue
        fi
        SUB="$t"; i=$((i+1)); break ;;
    esac
  done
  [ "$SUB" = "plan" ] && SAW_PLAN_SUBCMD=1
  case "$SUB" in
    apply|destroy) ;;
    *) [ "$SEG_WRITES" -eq 1 ] && SAW_WRITER=1; PREV_SEG="$SEG"; continue ;;
  esac

  HOWTO="Run the plan and review it first:@NL@  $BIN plan -out=tfplan@NL@  /whatbreaks:review tfplan@NL@then apply that exact file: $BIN apply tfplan. If the review verdict is BLOCK, the user must accept the risk themselves with /whatbreaks:approve tfplan before the apply is allowed."

  DESTROY=0; AUTO=0; PLANFILE=""; HELP=0
  [ "$SUB" = "destroy" ] && DESTROY=1
  while [ $i -lt "${#W[@]}" ]; do
    t="${W[$i]}"
    case "$t" in
      -help|--help|-h) HELP=1; i=$((i+1)) ;;
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
  if [ "$HELP" -eq 1 ]; then PREV_SEG="$SEG"; continue; fi

  # ---- decisions ----
  if [ "$RUNALL" -eq 1 ]; then
    deny "whatbreaks: terragrunt run-all $SUB applies every module at once with no per-module plan review. Run plan per module with an absolute -out path, review each with /whatbreaks:review, then apply the reviewed plan files one at a time."
  fi

  if [ -z "$PLANFILE" ]; then
    if [ "$DESTROY" -eq 1 ]; then
      deny "whatbreaks: $BIN destroy is blocked. Create a destroy plan instead:@NL@  $BIN plan -destroy -out=destroy.tfplan@NL@  /whatbreaks:review destroy.tfplan@NL@The verdict will normally be BLOCK (everything is destroyed), so the user must accept it themselves with /whatbreaks:approve destroy.tfplan before $BIN apply destroy.tfplan is allowed."
    fi
    if [ "$AUTO" -eq 1 ] || [ "$ENV_ARGS" -eq 1 ] || [ "$PIPED" -eq 1 ] || [ "$REDIRECT_IN" -eq 1 ]; then
      deny "whatbreaks: $BIN apply with -auto-approve (or a piped/env-injected approval) and no saved plan file would apply whatever the current plan is, unreviewed. $HOWTO"
    fi
    deny "whatbreaks: $BIN apply without a saved plan file cannot be reviewed before it runs. $HOWTO"
  fi

  # Anything earlier in the same command line that can (re)write files means the hash
  # checked now may not be the file terraform will read.
  if [ "$SAW_PLAN_SUBCMD" -eq 1 ] || [ "$SAW_WRITER" -eq 1 ]; then
    deny "whatbreaks: this command writes files (plan -out, cp, mv, curl, redirection, ...) and then applies in the same line, so the plan file cannot be verified. Run the plan first, then /whatbreaks:review $PLANFILE, then apply in a separate command."
  fi

  # Resolve the plan file. With -chdir, terraform resolves relative paths inside that directory.
  BASE="$EFFECTIVE_CWD"
  if [ -n "$CHDIR" ]; then
    case "$CHDIR" in /*) BASE="$CHDIR" ;; *) BASE="$EFFECTIVE_CWD/$CHDIR" ;; esac
  fi
  case "$PLANFILE" in /*) RESOLVED="$PLANFILE" ;; *) RESOLVED="$BASE/$PLANFILE" ;; esac
  if [ ! -f "$RESOLVED" ]; then
    deny "whatbreaks: plan file $PLANFILE was not found (looked in $BASE), so it cannot have been reviewed. With terragrunt, a relative -out path lands in .terragrunt-cache; re-plan with an absolute -out path. $HOWTO"
  fi

  [ -z "$MARKER_DIR" ] && deny "whatbreaks: no plugin data directory is available (CLAUDE_PLUGIN_DATA is unset), so reviews cannot be verified. Update Claude Code, or turn the gate off with the apply_gate option."
  HASH=$(sha256_of "$RESOLVED")
  [ -z "$HASH" ] && deny "whatbreaks: cannot hash $PLANFILE (no sha256sum, shasum, or openssl on PATH), so the review cannot be verified. $HOWTO"
  MARKER="$MARKER_DIR/$HASH.json"
  if [ ! -f "$MARKER" ]; then
    deny "whatbreaks: $PLANFILE has not been reviewed (no review marker for sha256 ${HASH:0:12}). Run /whatbreaks:review $PLANFILE first. Re-running plan produces a new file that needs its own review."
  fi
  APPROVED=$(marker_field "$MARKER" approved)
  VERDICT=$(marker_field "$MARKER" verdict)
  STATUS=$(marker_field "$MARKER" status)
  if [ "$APPROVED" = "true" ]; then PREV_SEG="$SEG"; continue; fi
  if [ "$VERDICT" = "block" ] || [ "$STATUS" = "blocked" ]; then
    deny "whatbreaks: the review of $PLANFILE ended in BLOCK (critical findings). Do not work around this. Restate the critical findings to the user; if they still want to apply, they must run /whatbreaks:approve $PLANFILE themselves. Only then is $BIN apply $PLANFILE allowed."
  fi
  if [ "$STATUS" = "reviewed" ] || [ "$STATUS" = "approved" ]; then PREV_SEG="$SEG"; continue; fi
  deny "whatbreaks: the review marker for $PLANFILE is incomplete (status=$STATUS verdict=$VERDICT). Re-run /whatbreaks:review $PLANFILE."
done <<EOF
$SEGS
EOF

allow
