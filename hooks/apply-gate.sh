#!/bin/bash
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
#   * A terraform binary is looked for anywhere in a simple command (wrappers, shells,
#     container images, remote-shell strings), not only in the first position; the only
#     commands exempt from that scan are ones that merely print or search text.
#   * The hash is trusted only when nothing earlier on the same line could have rewritten
#     the plan file: earlier commands must be known-harmless and must not mention the file.
#
# Disable with the plugin's `apply_gate` option (userConfig) — never by editing this file.
# Compatible with bash 3.2 (macOS). Plain bash: JSON fields are read with jq when it is
# installed and with the small parser below otherwise; shell words are split by the
# tokenizer below. No other interpreter or file is run.

set -u
LC_ALL=C   # byte-based string operations
TAB=$'\t'
WORD_CLASS='["'\''\\ '"$TAB"']'   # where a shell word may end or quoting starts
DQ_CLASS='["\\]'                   # inside "...": the closing quote or an escape
SQ_CLASS="['\\\\]"                 # inside $'...': the closing quote or an escape
SEP_CLASS='[;|&(){}`]'              # where a simple command may end
LT='<'; HD="$LT$LT"                 # the here-document operator, as data (never written out in this file)
BLANK_RUN_END='[! '"$TAB"']'        # the first character after a run of blanks
STEP_IFS=$'"\'\\ \t;&|(){}`'      # every character that costs the parsing below a step

# Cost discipline: the hook must finish well inside its timeout on every input, because a
# timed-out hook does not block. bash 3.2 (macOS) implements `${x//pat/rep}` and `${x##pat}`
# with a quadratic scan on long strings, so whole-command text work goes through tr/awk
# (linear) and the bash below only uses prefix/suffix cuts and offsets that cost one pass.
# The sizes it loops over are capped first (bytes, lines, parts, and words).

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

json_scalar() {
  # $1 = JSON text, $2 = key. Prints the value of the first `"key": value` pair (the key
  # followed by a colon; an escaped `\"key\"` inside a string value never qualifies): a
  # string with its escapes decoded, or a bare scalar (true, false, null, a number).
  # Prints nothing when the key is absent or its value is an object or array. \001 and
  # \002 stand in for escapes while the closing quote is found; JSON cannot contain
  # those bytes unescaped. awk keeps this linear on large inputs. (No split() here: the
  # one-true-awk splits on newlines as well as on a single-character separator.)
  printf '%s' "$1" | LC_ALL=C awk -v key="$2" '
    BEGIN { RS = "\001" }
    NR == 1 {
      s = $0; q = "\"" key "\""; pos = 1
      while (1) {
        i = index(substr(s, pos), q)
        if (i == 0) exit
        t = substr(s, pos + i - 1 + length(q))
        if (match(t, /^[ \t\r\n]*:/)) { s = substr(t, RLENGTH + 1); break }
        pos = pos + i
      }
      sub(/^[ \t\r\n]*/, "", s)
      if (substr(s, 1, 1) != "\"") {
        match(s, /^[A-Za-z0-9_.+-]*/); printf "%s", substr(s, 1, RLENGTH); exit
      }
      s = substr(s, 2)
      gsub(/\\\\/, "\001", s)
      gsub(/\\"/, "\002", s)
      i = index(s, "\""); if (i > 0) s = substr(s, 1, i - 1)
      gsub(/\002/, "\"", s)
      gsub(/\\n/, "\n", s); gsub(/\\t/, "\t", s); gsub(/\\r/, "", s)
      gsub(/\\b/, " ", s); gsub(/\\f/, " ", s); gsub(/\\\//, "/", s)
      bs = "\\"; gsub(/\001/, bs, s)   # one backslash: a "\\\\" replacement gives two on some awks
      printf "%s", s
      exit
    }'
}

json_field() {
  # $1 = jq path, $2 = key name for the built-in parser -> the field of the hook input
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$INPUT" | jq -r "$1 // empty" 2>/dev/null
  else
    json_scalar "$INPUT" "$2"
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
  local text
  if command -v jq >/dev/null 2>&1; then
    jq -r ".$2 // empty" "$1" 2>/dev/null | tr 'A-Z' 'a-z'
  else
    text=$(cat "$1" 2>/dev/null) || text=""
    json_scalar "$text" "$2" | tr 'A-Z' 'a-z'
  fi
}

tokenize() {
  # Split $1 into shell words the way the shell would, removing quotes and backslash
  # escapes and expanding nothing: TOK=(...). `'...'` is literal, `"..."` honours \" \\ \$
  # and \`, a backslash outside quotes protects the next character. An unterminated quote
  # runs to the end of the text. Long stretches of ordinary characters are skipped in one
  # pattern operation, so the cost grows with the number of quotes and spaces, not bytes.
  TOK=()
  local s="$1" cur="" inword=0 pre c
  while [ -n "$s" ]; do
    pre=${s%%$WORD_CLASS*}
    if [ -n "$pre" ]; then cur="$cur$pre"; inword=1; s=${s:${#pre}}; continue; fi
    c=${s:0:1}; s=${s:1}
    case "$c" in
      ' '|$'\t')
        if [ "$inword" -eq 1 ]; then TOK+=("$cur"); cur=""; inword=0; fi
        pre=${s%%$BLANK_RUN_END*}; s=${s:${#pre}} ;;   # skip the rest of the blank run in one step
      \\)
        if [ -n "$s" ]; then cur="$cur${s:0:1}"; s=${s:1}; fi
        inword=1 ;;
      \')
        inword=1
        if [ "${cur%\$}" != "$cur" ]; then
          # $'...' ANSI-C quoting: drop the $, and honour \' and \\ inside
          cur=${cur%\$}
          while [ -n "$s" ]; do
            pre=${s%%$SQ_CLASS*}; cur="$cur$pre"; s=${s:${#pre}}
            [ -z "$s" ] && break
            c=${s:0:1}; s=${s:1}
            [ "$c" = "'" ] && break
            case "${s:0:1}" in \'|\\) cur="$cur${s:0:1}"; s=${s:1} ;; *) cur="$cur\\" ;; esac
          done
        else
          pre=${s%%\'*}; cur="$cur$pre"
          if [ "$pre" = "$s" ]; then s=""; else s=${s:$((${#pre}+1))}; fi
        fi ;;
      \")
        inword=1
        while [ -n "$s" ]; do
          pre=${s%%$DQ_CLASS*}; cur="$cur$pre"; s=${s:${#pre}}
          [ -z "$s" ] && break
          c=${s:0:1}; s=${s:1}
          [ "$c" = '"' ] && break
          case "${s:0:1}" in
            \"|\\|\$|\`) cur="$cur${s:0:1}"; s=${s:1} ;;
            *) cur="$cur\\" ;;
          esac
        done ;;
    esac
  done
  [ "$inword" -eq 1 ] && TOK+=("$cur")
  return 0
}

split_ws() {
  # Split $1 on blanks only (no quote handling): PARTS=(...)
  set -f   # no globbing: word splitting is the point
  # shellcheck disable=SC2206
  PARTS=($1)
  set +f
}

base_of() {
  # R = the part of $1 after its last slash (one pass; `${x##*/}` is quadratic in bash 3.2)
  local d=${1%/*}
  if [ "$d" = "$1" ]; then R=$1; else R=${1:$((${#d}+1))}; fi
}

after_last() {
  # $1 = character, $2 = text -> R = the part of $2 after the last $1, or all of it
  local d=${2%"$1"*}
  if [ "$d" = "$2" ]; then R=$2; else R=${2:$((${#d}+1))}; fi
}

tf_name() {
  # R = the program name in token $1 stripped of $'…' quoting, path, flake#attr, .exe
  # and an image tag or digest; empty when the token is too long to be a program name.
  local b="$1"
  [ "${#b}" -gt 512 ] && b=${b:$((${#b}-512))}   # only the tail can hold the program name
  b=${b#\$}
  base_of "$b"; b=$R
  if [ "${#b}" -gt 256 ]; then R=""; return 0; fi    # not a program name
  after_last '#' "$b"; b=$R
  b=${b%.exe}; b=${b%%:*}; b=${b%%@*}
  R=$b
}

is_tf_binary() {
  tf_name "$1"
  case "$R" in terraform|tofu|opentofu|terragrunt|tf|tfenv|tgenv|tofuenv|terraform-*|terraform_*|tofu-*|tofu_*) return 0 ;; esac
  return 1
}

count_steps() {
  # R = how many quotes, backslashes, blank runs and separators $1 holds (one pass)
  local IFS="$STEP_IFS"
  set -f
  # shellcheck disable=SC2086
  set -- $1
  set +f
  R=$#
}

blank() { [ "$1" = ' ' ] || [ "$1" = "$TAB" ]; }

emit() {
  # used by split_segments: push the pending segment (with its marker) onto SEG_ARR
  if [ -n "$mark$seg" ]; then SEG_ARR+=("$mark$seg"); fi
  seg=""; mark=""
  if [ $((SEGCOUNT + ${#SEG_ARR[@]})) -gt 300 ]; then
    deny "whatbreaks: command has too many parts ($((SEGCOUNT + ${#SEG_ARR[@]}))) to gate safely; run the terraform step on its own."
  fi
}

split_segments() {
  # Cut line $1 into simple commands: SEG_ARR. A segment that follows `|` is marked
  # @PIPE@, one that starts a `$(` or backtick substitution @SUBST@, and the text after a
  # `)` @TAIL@. `>&`, `<&` and `&>` are redirections, not separators; `{`/`}` only
  # separate as words. One pass: each cut is a prefix operation plus an offset.
  SEG_ARR=()
  local rest="$1" seg="" mark="" pre c1 c2 prev
  while :; do
    pre=${rest%%$SEP_CLASS*}
    seg="$seg$pre"
    rest=${rest:${#pre}}
    [ -z "$rest" ] && break
    c1=${rest:0:1}; c2=${rest:1:1}
    if [ -n "$seg" ]; then prev=${seg:$((${#seg}-1)):1}; else prev=""; fi
    case "$c1" in
      ';') emit; rest=${rest:1} ;;
      '|') if [ "$c2" = '|' ]; then emit; rest=${rest:2}; else emit; mark="@PIPE@ "; rest=${rest:1}; fi ;;
      '&')
        if [ "$c2" = '&' ]; then emit; rest=${rest:2}
        elif [ "$prev" = '>' ] || [ "$prev" = '<' ] || [ "$c2" = '>' ]; then seg="$seg&"; rest=${rest:1}
        else emit; rest=${rest:1}; fi ;;
      '(') if [ "$prev" = '$' ]; then seg=${seg%\$}; emit; mark="@SUBST@ "; else emit; fi; rest=${rest:1} ;;
      ')') emit; mark="@TAIL@ "; rest=${rest:1} ;;
      '`') emit; mark="@SUBST@ "; rest=${rest:1} ;;
      '{') if blank "$prev" && { [ -z "$c2" ] || blank "$c2"; }; then emit; else seg="$seg{"; fi; rest=${rest:1} ;;
      '}') if blank "$prev"; then emit; else seg="$seg}"; fi; rest=${rest:1} ;;
    esac
  done
  emit
}

record_earlier() {
  # $1 = 1 when plain mentions of file names must be recorded (the command could write them),
  # then the tokens. Redirect targets are always recorded; an unresolvable target is unsafe.
  local mention="$1"; shift
  local expect_target=0 tok
  for tok in "$@"; do
    if [ "$expect_target" -eq 1 ]; then
      expect_target=0
      case "$tok" in *'$'*|*'*'*|*'?'*) UNRESOLVED_REDIRECT=1 ;; \&*) ;; *) base_of "$tok"; REDIRECT_TARGETS="$REDIRECT_TARGETS$R " ;; esac
      continue
    fi
    case "$tok" in
      \>|\>\>|[0-9]\>|[0-9]\>\>|\&\>|\&\>\>) expect_target=1 ;;
      \>*|[0-9]\>*|\&\>*)
        tok=${tok#\&}; tok=${tok#[0-9]}; tok=${tok#\>}; tok=${tok#\>}
        case "$tok" in *'$'*|*'*'*|*'?'*) UNRESOLVED_REDIRECT=1 ;; \&*|"") ;; *) base_of "$tok"; REDIRECT_TARGETS="$REDIRECT_TARGETS$R " ;; esac ;;
      *) if [ "$mention" -eq 1 ]; then base_of "$tok"; EARLIER_BASENAMES="$EARLIER_BASENAMES$R "; fi ;;
    esac
  done
}

# ---------------------------------------------------------------- input
INPUT=$(cat)
# Parsing below is linear in the input size, but a very large input would still take longer
# than the hook timeout (and a timed-out hook does not block): refuse it when it could
# concern terraform at all.
if [ "${#INPUT}" -gt 262144 ]; then
  case "$INPUT" in
    *terraform*|*tofu*|*terragrunt*|*tf*|*tgenv*) deny "whatbreaks: hook input is too large (${#INPUT} bytes) to parse safely; run the terraform step on its own." ;;
  esac
  allow
fi
CMD=$(json_field '.tool_input.command' 'command')

# Fail closed if the payload looks terraform-ish but could not be parsed.
if [ -z "$CMD" ]; then
  case "$INPUT" in
    *terraform*|*tofu*|*terragrunt*)
      case "$INPUT" in
        *apply*|*destroy*) deny "whatbreaks: could not read the command from the hook input, so refusing to gate blindly. If this persists, turn the gate off with the apply_gate option and report it." ;;
      esac ;;
  esac
  allow
fi

# Fast path on a de-quoted copy, so terr""aform or terra\form cannot slip past it.
FAST=$(printf '%s' "$CMD" | tr -d '"'"'"'\\')
FASTN=" $(printf '%s' "$FAST" | tr ';&|(){}\n\t' '         ') "
case "$FASTN" in
  *terraform*|*tofu*|*terragrunt*|*tfenv*|*tgenv*|*' tf '*) ;;
  *) allow ;;
esac

# A huge or very fragmented command could push the parsing below past the hook timeout, and
# a timed-out hook does not block. Refuse to gate it (the command mentions terraform, or the
# fast path would have allowed it already).
if [ "${#CMD}" -gt 131072 ]; then
  deny "whatbreaks: command is too long (${#CMD} bytes) to gate safely; run the terraform step on its own."
fi

# From here on any unexpected error must deny (exit 1 would be treated as non-blocking).
# shellcheck disable=SC2154  # rc is assigned inside the trap
trap 'rc=$?; if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then printf "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"whatbreaks: hook failed internally (exit %s); refusing to allow a terraform command blindly.\"}}\n" "$rc"; exit 2; fi' EXIT

# User switched the gate off via userConfig (CLAUDE_PLUGIN_OPTION_<KEY>).
GATE="${CLAUDE_PLUGIN_OPTION_APPLY_GATE:-${CLAUDE_PLUGIN_OPTION_apply_gate:-true}}"
case "$(printf '%s' "$GATE" | tr 'A-Z' 'a-z')" in
  false|0|no|off) allow ;;
esac

CWD=$(json_field '.cwd' 'cwd')
[ -z "$CWD" ] && CWD=$(pwd)
HOME="${HOME:-/nonexistent}"
MARKER_DIR=""
[ -n "${CLAUDE_PLUGIN_DATA:-}" ] && MARKER_DIR="$CLAUDE_PLUGIN_DATA/reviews"

# Env-var back doors that auto-approve or inject flags: treated like -auto-approve.
case "$CMD" in
  *TF_CLI_ARGS*|*TG_NON_INTERACTIVE*|*TERRAGRUNT_NON_INTERACTIVE*|*TF_INPUT=*) ENV_ARGS=1 ;;
  *) ENV_ARGS=0 ;;
esac

# ---------------------------------------------------------------- split into simple commands
# Physical lines first (heredoc bodies are line-based), then separators within a line.
SEGCOUNT=0
SPECIALS=0          # quotes, blanks, backslashes and separators seen so far (each costs a step)
LINES="$CMD"
PENDING=""          # a line ending in a backslash is continued on the next one

EFFECTIVE_CWD="$CWD"
LAST_CLASS=""       # classification of the previous simple command: text, harmless, tf, other
SAW_PLAN_SUBCMD=0   # an earlier command on this line ran `plan` (may have written the file)
SAW_UNSAFE=0        # an earlier command on this line is not known to be harmless
EARLIER_BASENAMES=" "   # basenames mentioned by earlier commands that could write them
REDIRECT_TARGETS=" "    # basenames of redirect targets in earlier segments
UNRESOLVED_REDIRECT=0   # an earlier redirect target that cannot be resolved (variable, glob)
PREV_SEG=""
HEREDOC_END=""

# Commands that only print, search, or edit text: a "terraform apply" inside their
# arguments is data, not an invocation.
TEXT_CONSUMERS="echo printf grep rg egrep fgrep git sed awk cat tee less more man head tail wc sort uniq cut tr vim vi nano code subl open pbcopy xclip diff comm"
# Commands that cannot rewrite a plan file (given they do not mention it): safe to precede an apply.
HARMLESS="cd pushd popd export unset set true false : echo printf ls pwd test [ [[ sleep date mkdir rm touch which type command hash whoami id uname clear history alias stat file du cmp md5sum sha256sum shasum"
# Commands that may mention the plan file without changing it (they only read it).
READ_ONLY_MENTIONERS="test [ [[ ls echo printf stat file du wc head cat less more diff cmp md5sum sha256sum shasum grep rg egrep fgrep"
TF_READONLY="init validate fmt show output version providers graph console test login logout workspace refresh get import taint untaint force-unlock metadata modules plan"

SHELLS="bash sh zsh dash ksh eval xargs find script expect ssh su runuser chroot"
GIT_MUTATING="checkout pull stash reset merge rebase restore switch clean apply am cherry-pick revert"

# Split the command into physical lines, and each line into simple commands, as arrays
# (no here-documents: the loops must run in this shell so state and exit codes carry).
split_lines() {
  local IFS=$'\n'; set -f   # no globbing: splitting on newlines is the point
  # shellcheck disable=SC2206
  LINE_ARR=($1)
  set +f
}

LINE_ARR=()
split_lines "$LINES"
if [ "${#LINE_ARR[@]}" -gt 2000 ]; then
  deny "whatbreaks: command has too many lines (${#LINE_ARR[@]}) to gate safely; run the terraform step on its own."
fi
for LINE in "${LINE_ARR[@]+"${LINE_ARR[@]}"}"; do
  # ---- here-document bodies are data; skip them until the terminator line
  if [ -n "$HEREDOC_END" ]; then
    t="$LINE"; lead=${t%%[![:space:]]*}; t=${t:${#lead}}
    [ "$t" = "$HEREDOC_END" ] && HEREDOC_END=""
    continue
  fi
  # ---- join backslash-newline continuations (only outside heredoc bodies)
  if [ -n "$PENDING" ]; then LINE="$PENDING $LINE"; PENDING=""; fi
  case "$LINE" in *\\) PENDING=${LINE%\\}; continue ;; esac
  # ---- bound the work below: every quote, blank, backslash and separator costs the
  # tokenizer or the segment loop a step, and a line made of thousands of them would take
  # longer than the hook timeout (a timed-out hook does not block).
  count_steps "$LINE"
  SPECIALS=$((SPECIALS + R))
  if [ "$SPECIALS" -gt 4000 ]; then
    deny "whatbreaks: command has too many words, quotes or parts ($SPECIALS) to gate safely; run the terraform step on its own."
  fi
  # ---- here-document start, detected on tokens so that a quoted operator does not count
  case "$LINE" in
    *"$HD"*)
      tokenize "$LINE"
      HT=("${TOK[@]+"${TOK[@]}"}")
      k=0
      while [ $k -lt "${#HT[@]}" ]; do
        tok="${HT[$k]}"
        case "$tok" in
          "$HD$LT"*) ;;                                     # a here-string carries no body
          "$HD"|"$HD-") if [ $((k+1)) -lt "${#HT[@]}" ]; then HEREDOC_END="${HT[$((k+1))]}"; fi; break ;;
          "$HD"*) tok=${tok#"$HD"}; tok=${tok#-}; HEREDOC_END="$tok"; break ;;
        esac
        k=$((k+1))
      done ;;
  esac

  LINE_COMPUTED=0
  case "$LINE" in *'$('*|*'`'*|*'${'*) LINE_COMPUTED=1 ;; esac

  SUBST_DEPTH=0; PRE_CLASS=""
  split_segments " $LINE"
  for SEG in "${SEG_ARR[@]+"${SEG_ARR[@]}"}"; do
    SEGCOUNT=$((SEGCOUNT+1))
    PIPED=0; COMPUTED=0; INHERIT_TEXT=0
    case "$SEG" in @PIPE@*) PIPED=1; SEG=${SEG#@PIPE@} ;; esac
    case "$SEG" in @SUBST@*) COMPUTED=1; SEG=${SEG#@SUBST@}; SUBST_DEPTH=$((SUBST_DEPTH+1)); PRE_CLASS="$LAST_CLASS" ;; esac
    case "$SEG" in @TAIL@*)
      SEG=${SEG#@TAIL@}
      if [ "$SUBST_DEPTH" -gt 0 ]; then
        SUBST_DEPTH=$((SUBST_DEPTH-1))
        # the text after a $(...) belongs to the command that contained it
        [ "$PRE_CLASS" = "text" ] && INHERIT_TEXT=1
      fi ;;
    esac
    case "$SEG" in *'$'*) COMPUTED=1 ;; esac
    REDIRECT_IN=0
    case "$SEG" in *'<'*) REDIRECT_IN=1 ;; esac

    # ---- tokenize into shell words (quotes removed, nothing expanded)
    tokenize "$SEG"
    W=()
    for tok in "${TOK[@]+"${TOK[@]}"}"; do W+=("${tok:0:4096}"); done
    if [ "${#W[@]}" -eq 0 ]; then PREV_SEG="$SEG"; continue; fi

    # drop a trailing comment (a token that *starts* with #)
    N=0
    for tok in "${W[@]+"${W[@]}"}"; do
      case "$tok" in \#*) break ;; esac
      N=$((N+1))
    done
    [ "$N" -eq 0 ] && { PREV_SEG="$SEG"; continue; }

    # ---- strip leading control words and variable assignments, remember `cd`
    i=0
    while [ $i -lt "$N" ]; do
      t="${W[$i]}"
      case "$t" in
        for|select|case|function) i="$N"; break ;;              # loop/case headers: no command here
        then|do|else|elif|'!'|if|while|until|fi|done|'esac'|in) i=$((i+1)); continue ;;
        [A-Za-z_]*=*) i=$((i+1)); continue ;;
      esac
      break
    done
    if [ $i -ge "$N" ]; then LAST_CLASS="harmless"; PREV_SEG="$SEG"; continue; fi
    FIRST="${W[$i]}"; base_of "$FIRST"; FIRSTBASE=$R
    if [ "$INHERIT_TEXT" -eq 1 ]; then LAST_CLASS="text"; PREV_SEG="$SEG"; continue; fi

    if [ "$FIRSTBASE" = "cd" ] || [ "$FIRSTBASE" = "pushd" ]; then
      if [ $((i+1)) -lt "$N" ]; then
        d="${W[$((i+1))]}"
        case "$d" in /*) EFFECTIVE_CWD="$d" ;; "~"*) EFFECTIVE_CWD="$HOME${d#\~}" ;; *) EFFECTIVE_CWD="$EFFECTIVE_CWD/$d" ;; esac
      fi
      LAST_CLASS="harmless"; PREV_SEG="$SEG"; continue
    fi

    # `echo terraform apply x | bash` (also behind sudo): a shell reading its script from a pipe
    if [ "$PIPED" -eq 1 ]; then
      shell_tok=""
      for tok in "${W[@]+"${W[@]}"}"; do base_of "$tok"; case "$R" in bash|sh|zsh|dash|ksh) shell_tok="$tok" ;; esac; done
      case "$shell_tok" in
        ?*)
          has_c=0
          for tok in "${W[@]+"${W[@]}"}"; do case "$tok" in -c|-*c*) has_c=1 ;; esac; done
          if [ "$has_c" -eq 0 ]; then
            case "$PREV_SEG" in *terraform*|*tofu*|*terragrunt*|*' tf '*|'tf '*)
              case "$PREV_SEG" in *apply*|*destroy*)
                deny "whatbreaks: a terraform apply/destroy piped into a shell cannot be reviewed. Run the plan, review it with /whatbreaks:review, then apply the reviewed plan file directly." ;;
              esac ;;
            esac
          fi ;;
      esac
    fi

    # ---- find the terraform binary anywhere in the command (wrappers, shells, remote shells, containers)
    # unless the command only consumes text.
    IS_TEXT=0
    for c in $TEXT_CONSUMERS; do [ "$FIRSTBASE" = "$c" ] && IS_TEXT=1; done
    IS_HARMLESS=0
    for c in $HARMLESS; do [ "$FIRSTBASE" = "$c" ] && IS_HARMLESS=1; done
    SCAN=1
    [ "$IS_TEXT" -eq 1 ] && SCAN=0
    case "$FIRSTBASE" in
      command) if [ $((i+1)) -lt "$N" ]; then case "${W[$((i+1))]}" in -v|-V|-p) SCAN=0 ;; esac; fi ;;
      exec) ;;
      *) [ "$IS_HARMLESS" -eq 1 ] && SCAN=0 ;;    # `which terraform`, `ls tf`: an argument, not an invocation
    esac
    FOUND=-1
    if [ "$SCAN" -eq 1 ]; then
      # First look at the tokens as quoted (so "my plan.tfplan" stays one argument).
      j=$i
      while [ $j -lt "$N" ]; do
        if is_tf_binary "${W[$j]}"; then FOUND=$j; break; fi
        j=$((j+1))
      done
      HAS_SHELL=0
      for tok in "${W[@]+"${W[@]}"}"; do
        case "$tok" in */*) base_of "$tok" ;; *) R=$tok ;; esac
        case " $SHELLS " in *" $R "*) HAS_SHELL=1 ;; esac
        case "$tok" in -c|--run|--command|--eval) HAS_SHELL=1 ;; esac   # a wrapper taking a command string
      done
      if [ "$FOUND" -lt 0 ] && [ "$HAS_SHELL" -eq 1 ]; then
        # Not found: re-split every token on whitespace so that a quoted "terraform apply x"
        # handed to a shell, a remote shell, xargs, or a wrapper becomes separate words, and
        # scan again.
        NEWW=()
        j=$i
        while [ $j -lt "$N" ]; do
          split_ws "${W[$j]}"
          for q in "${PARTS[@]+"${PARTS[@]}"}"; do NEWW+=("$q"); done
          j=$((j+1))
        done
        j=0
        while [ $j -lt "${#NEWW[@]}" ]; do
          if is_tf_binary "${NEWW[$j]}"; then FOUND=$j; break; fi
          j=$((j+1))
        done
        if [ "$FOUND" -ge 0 ]; then
          W=("${NEWW[@]+"${NEWW[@]}"}"); N="${#W[@]}"
        fi
      fi
    fi

    if [ "$FOUND" -lt 0 ] && [ "$SCAN" -eq 1 ]; then
      # `$TF apply x`, `sudo "$BIN" -chdir=d destroy`: the program right before the subcommand
      # (skipping its flags) is named through a variable, so the binary cannot be seen. The
      # command as a whole mentions terraform (it passed the fast path), so refuse rather than
      # guess. `kubectl apply` and friends name their program plainly and are left alone.
      j=$i
      while [ $j -lt "$N" ]; do
        case "${W[$j]}" in
          apply|destroy)
            k=$((j-1))
            while [ $k -gt $i ]; do case "${W[$k]}" in -*) k=$((k-1)) ;; *) break ;; esac; done
            if [ $k -ge $i ]; then
              case "${W[$k]}" in
                \$*) deny "whatbreaks: the program running ${W[$j]} is named through a variable (${W[$k]}), so it cannot be checked. Write it out plainly: terraform plan -out=tfplan, /whatbreaks:review tfplan, terraform apply tfplan." ;;
              esac
            fi ;;
        esac
        j=$((j+1))
      done
    fi
    if [ "$FOUND" -lt 0 ]; then
      # Not a terraform command. Is it harmless to run before an apply on the same line?
      harmless=0
      [ "$IS_HARMLESS" -eq 1 ] && harmless=1
      [ "$IS_TEXT" -eq 1 ] && harmless=1
      if [ "$FIRSTBASE" = "git" ] && [ $((i+1)) -lt "$N" ]; then
        for c in $GIT_MUTATING; do [ "${W[$((i+1))]}" = "$c" ] && harmless=0; done   # can restore a tracked plan file
      fi
      [ "$harmless" -eq 0 ] && SAW_UNSAFE=1
      mention=1
      for c in $READ_ONLY_MENTIONERS; do [ "$FIRSTBASE" = "$c" ] && mention=0; done
      record_earlier "$mention" "${W[@]+"${W[@]}"}"
      if [ "$IS_TEXT" -eq 1 ]; then LAST_CLASS="text"; elif [ "$harmless" -eq 1 ]; then LAST_CLASS="harmless"; else LAST_CLASS="other"; fi
      PREV_SEG="$SEG"; continue
    fi
    LAST_CLASS="tf"

    tf_name "${W[$FOUND]}"; BIN=$R
    i=$((FOUND+1))

    CHDIR=""; SUB=""; RUNALL=0; HELP=0
    while [ $i -lt "$N" ]; do
      t="${W[$i]}"
      case "$t" in
        -chdir=*) CHDIR=${t#-chdir=}; i=$((i+1)) ;;
        --all) RUNALL=1; i=$((i+1)) ;;
        -help|--help|-h) HELP=1; i=$((i+1)) ;;
        [0-9]\>*|[0-9]\<*|\>*|\<*) i=$((i+1)) ;;               # a redirection before the subcommand
        -*) i=$((i+1)) ;;
        run-all) RUNALL=1; i=$((i+1)) ;;
        run|stack|exec) i=$((i+1)) ;;
        *)
          if is_tf_binary "$t"; then
            tf_name "$t"; BIN=$R; i=$((i+1)); continue
          fi
          SUB="$t"; i=$((i+1)); break ;;
      esac
    done
    if [ "$HELP" -eq 1 ]; then PREV_SEG="$SEG"; continue; fi
    [ "$SUB" = "plan" ] && SAW_PLAN_SUBCMD=1

    KNOWN=0
    for c in $TF_READONLY apply destroy; do [ "$SUB" = "$c" ] && KNOWN=1; done
    if [ "$KNOWN" -eq 0 ]; then
      # e.g. `docker run --entrypoint terraform image:tag apply tfplan`: the real subcommand comes later
      j=$i
      while [ $j -lt "$N" ]; do
        case "${W[$j]}" in apply|destroy) SUB="${W[$j]}"; i=$((j+1)); KNOWN=1; break ;; esac
        j=$((j+1))
      done
    fi
    if [ "$KNOWN" -eq 0 ] && { [ "$COMPUTED" -eq 1 ] || [ "$LINE_COMPUTED" -eq 1 ]; }; then
      deny "whatbreaks: the $BIN subcommand is computed at run time (a variable, substitution, or quoting trick), so it cannot be checked. Write the command out plainly: $BIN plan -out=tfplan, /whatbreaks:review tfplan, $BIN apply tfplan."
    fi
    case "$SUB" in
      apply|destroy) ;;
      *)
        # any other terraform subcommand cannot rewrite a plan file; only its redirects matter
        record_earlier 0 "${W[@]+"${W[@]}"}"
        PREV_SEG="$SEG"; continue ;;
    esac

    HOWTO="Run the plan and review it first:@NL@  $BIN plan -out=tfplan@NL@  /whatbreaks:review tfplan@NL@then apply that exact file: $BIN apply tfplan. If the review verdict is BLOCK, the user must accept the risk themselves with /whatbreaks:approve tfplan before the apply is allowed."

    DESTROY=0; AUTO=0; PLANFILE=""
    [ "$SUB" = "destroy" ] && DESTROY=1
    while [ $i -lt "$N" ]; do
      t="${W[$i]}"
      case "$t" in
        -help|--help|-h) HELP=1; i=$((i+1)) ;;
        --) i=$((i+1)); if [ $i -lt "$N" ] && [ -z "$PLANFILE" ]; then PLANFILE="${W[$i]}"; fi; break ;;
        -destroy|--destroy) DESTROY=1; i=$((i+1)) ;;
        -auto-approve|--auto-approve|-auto-approve=true|--auto-approve=true) AUTO=1; i=$((i+1)) ;;
        --terragrunt-non-interactive|--non-interactive) AUTO=1; i=$((i+1)) ;;
        -var|-var-file|-target|-replace|-exclude|-parallelism|-backup|-state|-state-out|-lock-timeout|\
        --terragrunt-working-dir|--working-dir|--terragrunt-config|--config|--terragrunt-iam-role|--iam-role|\
        --terragrunt-include-dir|--queue-include-dir|--terragrunt-exclude-dir|--queue-exclude-dir|\
        --terragrunt-download-dir|--download-dir|--terragrunt-parallelism|--terragrunt-log-level|--log-level|\
        --terragrunt-source|--source|--terragrunt-source-map|--terragrunt-strict-control|--strict-control)
          i=$((i+2)) ;;
        [0-9]\>*|[0-9]\<*|\>*|\<*) i=$((i+1)) ;;
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
        deny "whatbreaks: $BIN apply with -auto-approve (or an approval injected through a pipe or a variable) and no saved plan file would apply whatever the current plan is, unreviewed. $HOWTO"
      fi
      deny "whatbreaks: $BIN apply without a saved plan file cannot be reviewed before it runs. $HOWTO"
    fi
    case "$PLANFILE" in
      *'$'*|*'`'*) deny "whatbreaks: the plan file name is computed at run time ($PLANFILE), so the reviewed file cannot be identified. Name the file plainly." ;;
    esac

    # Anything earlier on the same line that is not known-harmless, ran `plan`, or mentioned
    # this file by name could have rewritten it: the hash checked now may not be what
    # terraform reads.
    base_of "$PLANFILE"; PLANBASE=$R
    case "$EARLIER_BASENAMES" in *" $PLANBASE "*) SAW_UNSAFE=1 ;; esac
    case "$REDIRECT_TARGETS" in *" $PLANBASE "*) SAW_UNSAFE=1 ;; esac
    if [ "$SAW_PLAN_SUBCMD" -eq 1 ] || [ "$SAW_UNSAFE" -eq 1 ] || [ "$UNRESOLVED_REDIRECT" -eq 1 ]; then
      deny "whatbreaks: something earlier in this command (plan -out, a copy, a redirection, or a command that could write files) runs before the apply, so the plan file cannot be verified. Run the plan first, then /whatbreaks:review $PLANFILE, then apply in a separate command."
    fi

    # Resolve the plan file. With -chdir, terraform resolves relative paths inside that directory.
    BASE="$EFFECTIVE_CWD"
    if [ -n "$CHDIR" ]; then
      case "$CHDIR" in /*) BASE="$CHDIR" ;; *) BASE="$EFFECTIVE_CWD/$CHDIR" ;; esac
    fi
    case "$PLANFILE" in /*) RESOLVED="$PLANFILE" ;; "~"*) RESOLVED="$HOME${PLANFILE#\~}" ;; *) RESOLVED="$BASE/$PLANFILE" ;; esac
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
  done
done

allow
