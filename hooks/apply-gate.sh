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
# Compatible with bash 3.2 (macOS). Plain bash: the hook input is parsed and shell words
# are split by the functions below; nothing is run except a hash tool (sha256sum, shasum
# or openssl) on the plan file. No other interpreter, file, or command output is used.

set -u
LC_ALL=C   # byte-based string operations
printf -v TAB '\t'; printf -v NL '\n'          # a tab and a newline, as data
printf -v WORD_CLASS '[%s\\\\ \t]' "\"'"     # where a shell word may end or quoting starts
printf -v QUOTE_CLASS '[%s\\\\]' "\"'"       # a quote or a backslash
DQ_CLASS='["\\]'                          # inside "...": the closing quote or an escape
SQ_CLASS="['\\\\]"                        # inside a dollar-quoted word: the closing quote or an escape
SEP_CLASS='[;|&(){}`]'                     # where a simple command may end
printf -v BLANK_RUN_END '[! \t]'          # the first character after a run of blanks
printf -v HD '%s%s' '<' '<'                # the here-document operator, as data (never written out in this file)
printf -v STEP_IFS '%s\\ \t;&|(){}`' "\"'"  # every character that costs the parsing below a step
printf -v QUOTE_IFS '%s\\' "\"'"           # quotes and backslashes, for counting
printf -v DOLLAR '\044'                    # the dollar sign, as data
printf -v SUBST_OPEN '\044('               # the substitution opener, as data
printf -v BRACE_OPEN '\044{'               # the brace-expansion opener, as data

# Cost discipline: the hook must finish well inside its timeout on every input, because a
# timed-out hook does not block. bash 3.2 (macOS) implements `${x//pat/rep}` and `${x##pat}`
# with a quadratic scan on long strings, so the code below only uses prefix/suffix cuts and
# offsets that cost one sweep, and caps the sizes it loops over first (bytes, quotes, lines,
# parts and words). Everything is done in this shell: no command substitution, no other
# interpreter; the only external programs are the hash tools.

# ---------------------------------------------------------------- output helpers
deny() {
  # $1 = reason. Newlines are written as @NL@. The reason is JSON-escaped so that
  # user-controlled text (a plan file name) can never produce invalid JSON, and the
  # script exits 2, which blocks the tool call even if the JSON were unreadable.
  local reason=$1 msg=$1
  reason=${reason//\\/\\\\}
  reason=${reason//\"/\\\"}
  reason=${reason//[[:cntrl:]]/}
  reason=${reason//@NL@/\\n}
  msg=${msg//@NL@/ }
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$reason"
  printf '%s\n' "$msg" >&2
  exit 2
}
allow() { exit 0; }

json_string() {
  # $1 = field name. R = the string value of the first `"name": "..."` pair in INPUT with its
  # escapes decoded, or empty when the field is absent or its value is not a string. An
  # escaped `\"name\"` inside a string value never matches, because the quote after the
  # name is preceded by a backslash there. The text is scanned in 1 KiB windows (an escape
  # cut by a window boundary is carried over); each window's text is gathered in a small
  # string and the windows are joined once at the end, so the cost stays linear: bash
  # walks the whole string on every cut, so cuts must be made on short strings.
  local s name="\"$1\"" pre c win acc i n esc
  local -a parts
  R=""
  case "$INPUT" in *"$name"*) ;; *) return 0 ;; esac
  s=${INPUT#*"$name"}
  pre=${s%%[![:space:]]*}; s=${s:${#pre}}
  [ "${s:0:1}" = ":" ] || return 0
  s=${s:1}
  pre=${s%%[![:space:]]*}; s=${s:${#pre}}
  [ "${s:0:1}" = '"' ] || return 0
  s=${s:1}
  n=${#s}; i=0; esc=0; parts=()
  while [ "$i" -lt "$n" ]; do
    win=${s:i:1024}; i=$((i+${#win}))
    acc=""
    while [ -n "$win" ]; do
      if [ "$esc" -eq 0 ]; then
        pre=${win%%$DQ_CLASS*}
        acc="$acc$pre"
        win=${win:${#pre}}
        [ -z "$win" ] && break
        c=${win:0:1}; win=${win:1}
        if [ "$c" = '"' ]; then i=$n; break; fi   # the closing quote
        esc=1                                     # a backslash: the next character is escaped
        [ -z "$win" ] && break                    # ... and it starts the next window
      fi
      c=${win:0:1}; win=${win:1}; esc=0           # the character after a backslash
      case "$c" in
        n) acc="$acc$NL" ;;
        t) acc="$acc$TAB" ;;
        r|b|f) ;;
        u) acc="$acc"'\u' ;;                      # \uXXXX is left as written; it cannot form a shell word boundary
        *) acc="$acc$c" ;;
      esac
    done
    parts+=("$acc")
  done
  if [ "${#parts[@]}" -gt 0 ]; then local IFS=''; R="${parts[*]}"; fi
}

dequote() {
  # R = $1 with every quote and backslash removed (windowed, joined once: linear)
  local s="$1" pre win acc i=0 n=${#1}
  local -a parts
  R=""; parts=()
  while [ "$i" -lt "$n" ]; do
    win=${s:i:1024}; i=$((i+${#win}))
    acc=""
    while [ -n "$win" ]; do
      pre=${win%%$QUOTE_CLASS*}
      acc="$acc$pre"
      win=${win:${#pre}}
      [ -z "$win" ] && break
      win=${win:1}
    done
    parts+=("$acc")
  done
  if [ "${#parts[@]}" -gt 0 ]; then local IFS=''; R="${parts[*]}"; fi
}

count_words() {
  # R = how many pieces $1 falls into on the characters in $2, stopping just past $3
  local IFS="$2" n=0 w
  set -f
  # shellcheck disable=SC2034  # only the count matters
  for w in $1; do
    n=$((n+1))
    [ "$n" -gt "$3" ] && break
  done
  set +f
  R=$n
}

read_marker() {
  # $1 = marker file (one field per line, written by the review scripts). Sets M_APPROVED,
  # M_VERDICT and M_STATUS from the last matching lines; a field that only appears escaped
  # inside a string value (\"status\") has no quote right after its name and never matches.
  local line lead v
  M_APPROVED=""; M_VERDICT=""; M_STATUS=""
  while IFS= read -r line || [ -n "$line" ]; do
    lead=${line%%[![:space:]]*}; line=${line:${#lead}}   # the field name starts the line
    case "$line" in
      '"approved":'*|'"verdict":'*|'"status":'*)
        v=${line#*:}
        lead=${v%%[![:space:]]*}; v=${v:${#lead}}
        v=${v#\"}; v=${v%%[\",]*}
        case "$line" in
          '"approved":'*) M_APPROVED=$v ;;
          '"verdict":'*) M_VERDICT=$v ;;
          *) M_STATUS=$v ;;
        esac ;;
    esac
  done < "$1"
}

gate_by_hash() {
  # Runs as the consumer of the hash tool's output, with PLANFILE, BIN, MARKER_DIR set.
  # Reads the hash, checks the marker, and either denies (exit 2) or returns 0.
  local HASH rest MARKER
  IFS=' ' read -r HASH rest || HASH=""
  [ -z "$HASH" ] && deny "whatbreaks: cannot hash $PLANFILE, so the review cannot be verified. $HOWTO"
  MARKER="$MARKER_DIR/$HASH.json"
  if [ ! -f "$MARKER" ]; then
    deny "whatbreaks: $PLANFILE has not been reviewed (no review marker for sha256 ${HASH:0:12}). Run /whatbreaks:review $PLANFILE first. Re-running plan produces a new file that needs its own review."
  fi
  read_marker "$MARKER"
  case "$M_APPROVED" in [Tt][Rr][Uu][Ee]) return 0 ;; esac
  case "$M_VERDICT$M_STATUS" in
    *[Bb][Ll][Oo][Cc][Kk]*)
      deny "whatbreaks: the review of $PLANFILE ended in BLOCK (critical findings). Do not work around this. Restate the critical findings to the user; if they still want to apply, they must run /whatbreaks:approve $PLANFILE themselves. Only then is $BIN apply $PLANFILE allowed." ;;
  esac
  case "$M_STATUS" in [Rr][Ee][Vv][Ii][Ee][Ww][Ee][Dd]|[Aa][Pp][Pp][Rr][Oo][Vv][Ee][Dd]) return 0 ;; esac
  deny "whatbreaks: the review marker for $PLANFILE is incomplete (status=$M_STATUS verdict=$M_VERDICT). Re-run /whatbreaks:review $PLANFILE."
}

tokenize() {
  # Split $1 into shell words the way the shell would, removing quotes and backslash
  # escapes and expanding nothing: WORDS=(...). `'...'` is literal, `"..."` honours the
  # escaped quote, backslash, dollar and backtick, a backslash outside quotes protects the next character, and a dollar-quoted
  # word honours \' and \\. An unterminated quote runs to the end of the text. The text is
  # scanned in 1 KiB windows with the quoting state carried across them, so that every cut
  # is made on a short string (bash walks the whole string on each cut); runs of ordinary
  # characters and of blanks cost one step each.
  WORDS=()
  local s="$1" n=${#1} i=0 win pre c cur="" inword=0 mode=plain esc=0
  while [ "$i" -lt "$n" ]; do
    win=${s:i:1024}; i=$((i+${#win}))
    while [ -n "$win" ]; do
      if [ "$esc" -eq 1 ]; then                 # a backslash ended the previous window
        esc=0; c=${win:0:1}
        case "$mode" in
          plain) cur="$cur$c"; win=${win:1} ;;
          dq) case "$c" in \"|\\|"$DOLLAR"|\`) cur="$cur$c"; win=${win:1} ;; *) cur="$cur\\" ;; esac ;;
          *) case "$c" in \'|\\) cur="$cur$c"; win=${win:1} ;; *) cur="$cur\\" ;; esac ;;
        esac
        continue
      fi
      case "$mode" in
        plain)
          pre=${win%%$WORD_CLASS*}
          if [ -n "$pre" ]; then cur="$cur$pre"; inword=1; win=${win:${#pre}}; continue; fi
          c=${win:0:1}; win=${win:1}
          case "$c" in
            ' '|"$TAB")
              if [ "$inword" -eq 1 ]; then WORDS+=("$cur"); cur=""; inword=0; fi
              pre=${win%%$BLANK_RUN_END*}; win=${win:${#pre}} ;;   # skip the rest of the blank run in one step
            \\)
              inword=1
              if [ -n "$win" ]; then cur="$cur${win:0:1}"; win=${win:1}; else esc=1; fi ;;
            \')
              inword=1
              if [ "${cur%"$DOLLAR"}" != "$cur" ]; then cur=${cur%"$DOLLAR"}; mode=sq; else mode=lit; fi ;;
            \") inword=1; mode=dq ;;
          esac ;;
        lit)                                      # inside '...'
          pre=${win%%\'*}; cur="$cur$pre"
          if [ "$pre" = "$win" ]; then win=""; else win=${win:${#pre}+1}; mode=plain; fi ;;
        dq)                                       # inside "..."
          pre=${win%%$DQ_CLASS*}; cur="$cur$pre"; win=${win:${#pre}}
          [ -z "$win" ] && break
          c=${win:0:1}; win=${win:1}
          if [ "$c" = '"' ]; then mode=plain; continue; fi
          if [ -z "$win" ]; then esc=1; continue; fi
          case "${win:0:1}" in \"|\\|"$DOLLAR"|\`) cur="$cur${win:0:1}"; win=${win:1} ;; *) cur="$cur\\" ;; esac ;;
        sq)                                       # inside a dollar-quoted word
          pre=${win%%$SQ_CLASS*}; cur="$cur$pre"; win=${win:${#pre}}
          [ -z "$win" ] && break
          c=${win:0:1}; win=${win:1}
          if [ "$c" = "'" ]; then mode=plain; continue; fi
          if [ -z "$win" ]; then esc=1; continue; fi
          case "${win:0:1}" in \'|\\) cur="$cur${win:0:1}"; win=${win:1} ;; *) cur="$cur\\" ;; esac ;;
      esac
    done
  done
  [ "$inword" -eq 1 ] && WORDS+=("$cur")
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
  # R = the part of $1 after its last slash (one sweep; `${x##*/}` is quadratic in bash 3.2)
  local d=${1%/*}
  if [ "$d" = "$1" ]; then R=$1; else R=${1:$((${#d}+1))}; fi
}

after_last() {
  # $1 = character, $2 = text -> R = the part of $2 after the last $1, or all of it
  local d=${2%"$1"*}
  if [ "$d" = "$2" ]; then R=$2; else R=${2:$((${#d}+1))}; fi
}

tf_name() {
  # R = the program name in word $1 stripped of dollar-quoting, path, flake#attr, .exe
  # and an image tag or digest; empty when the word is too long to be a program name.
  local b="$1"
  [ "${#b}" -gt 512 ] && b=${b:$((${#b}-512))}   # only the tail can hold the program name
  b=${b#"$DOLLAR"}
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
  # @PIPE@, one that starts a dollar-paren or backtick substitution @SUBST@, and the text after a
  # `)` @TAIL@. `>&`, `<&` and `&>` are redirections, not separators; `{`/`}` only
  # separate as words. One sweep: each cut is a prefix operation plus an offset.
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
      '(') if [ "$prev" = "$DOLLAR" ]; then seg=${seg%"$DOLLAR"}; emit; mark="@SUBST@ "; else emit; fi; rest=${rest:1} ;;
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
  local expect_target=0 wd
  for wd in "$@"; do
    if [ "$expect_target" -eq 1 ]; then
      expect_target=0
      case "$wd" in *"$DOLLAR"*|*'*'*|*'?'*) UNRESOLVED_REDIRECT=1 ;; \&*) ;; *) base_of "$wd"; REDIRECT_TARGETS="$REDIRECT_TARGETS$R " ;; esac
      continue
    fi
    case "$wd" in
      \>|\>\>|[0-9]\>|[0-9]\>\>|\&\>|\&\>\>) expect_target=1 ;;
      \>*|[0-9]\>*|\&\>*)
        wd=${wd#\&}; wd=${wd#[0-9]}; wd=${wd#\>}; wd=${wd#\>}
        case "$wd" in *"$DOLLAR"*|*'*'*|*'?'*) UNRESOLVED_REDIRECT=1 ;; \&*|"") ;; *) base_of "$wd"; REDIRECT_TARGETS="$REDIRECT_TARGETS$R " ;; esac ;;
      *) if [ "$mention" -eq 1 ]; then base_of "$wd"; EARLIER_BASENAMES="$EARLIER_BASENAMES$R "; fi ;;
    esac
  done
}

# ---------------------------------------------------------------- input
INPUT=""
IFS= read -r -d '' INPUT || true
# Nothing to gate unless a terraform-family name appears at all. Beyond that, a very large
# or escape-heavy input would take longer than the hook timeout to parse (a timed-out hook
# does not block), so it is refused when it names one.
case "$INPUT" in
  *terraform*|*tofu*|*terragrunt*|*tfenv*|*tgenv*) ;;
  *tf*) ;;
  *) allow ;;
esac
if [ "${#INPUT}" -gt 262144 ]; then
  case "$INPUT" in
    *terraform*|*tofu*|*terragrunt*|*tfenv*|*tgenv*) deny "whatbreaks: hook input is too large (${#INPUT} bytes) to parse safely; run the terraform step on its own." ;;
  esac
  allow
fi
count_words "$INPUT" "$QUOTE_IFS" 50000
if [ "$R" -gt 50000 ]; then
  case "$INPUT" in
    *terraform*|*tofu*|*terragrunt*|*tfenv*|*tgenv*) deny "whatbreaks: hook input has too many quotes or escapes to parse safely; run the terraform step on its own." ;;
  esac
  allow
fi
json_string command; CMD=$R

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
dequote "$CMD"; FAST=$R
case "$FAST" in
  *terraform*|*tofu*|*terragrunt*|*tfenv*|*tgenv*) ;;
  *)
    case " $FAST " in
      *[!A-Za-z0-9_./-]tf[!A-Za-z0-9_./-]*) ;;     # the `tf` alias as a word
      *) allow ;;
    esac ;;
esac

# A huge or very fragmented command could push the parsing below past the hook timeout, and
# a timed-out hook does not block. Refuse to gate it (the command mentions terraform, or the
# fast path would have allowed it already).
if [ "${#CMD}" -gt 131072 ]; then
  deny "whatbreaks: command is too long (${#CMD} bytes) to gate safely; run the terraform step on its own."
fi

# From here on any unexpected error must deny (exit 1 would be treated as non-blocking).
on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"whatbreaks: hook failed internally (exit %s); refusing to allow a terraform command blindly."}}\n' "$rc"
    exit 2
  fi
}
trap on_exit EXIT

# User switched the gate off via userConfig (CLAUDE_PLUGIN_OPTION_<OPTION>).
GATE="${CLAUDE_PLUGIN_OPTION_APPLY_GATE:-${CLAUDE_PLUGIN_OPTION_apply_gate:-true}}"
case "$GATE" in
  [Ff][Aa][Ll][Ss][Ee]|0|[Nn][Oo]|[Oo][Ff][Ff]) allow ;;
esac

json_string cwd; CWD=$R
[ -z "$CWD" ] && CWD=.
HOMEDIR=~
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
HARMLESS="cd pushd popd export unset set true false : echo printf ls test [ [[ sleep date mkdir rm touch which type command hash whoami id uname clear history alias stat file du cmp md5sum sha256sum shasum"
# Commands that may mention the plan file without changing it (they only read it).
READ_ONLY_MENTIONERS="test [ [[ ls echo printf stat file du wc head cat less more diff cmp md5sum sha256sum shasum grep rg egrep fgrep"
TF_READONLY="init validate fmt show output version providers graph console test workspace refresh get import taint untaint force-unlock metadata modules plan"

SHELLS="bash sh zsh dash ksh eval xargs find script expect ssh su runuser chroot"
GIT_MUTATING="checkout pull stash reset merge rebase restore switch clean apply am cherry-pick revert"

# Split the command into physical lines, and each line into simple commands, as arrays
# (no here-documents: the loops must run in this shell so state and exit codes carry).
split_lines() {
  local IFS="$NL"; set -f   # no globbing: splitting on newlines is the point
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
  count_words "$LINE" "$STEP_IFS" 4000
  SPECIALS=$((SPECIALS + R))
  if [ "$SPECIALS" -gt 4000 ]; then
    deny "whatbreaks: command has too many words, quotes or parts ($SPECIALS) to gate safely; run the terraform step on its own."
  fi
  # ---- here-document start, detected on tokens so that a quoted operator does not count
  case "$LINE" in
    *"$HD"*)
      tokenize "$LINE"
      HT=("${WORDS[@]+"${WORDS[@]}"}")
      k=0
      while [ $k -lt "${#HT[@]}" ]; do
        wd="${HT[$k]}"
        case "$wd" in
          "$HD<"*) ;;                                       # a here-string carries no body
          "$HD"|"$HD-") if [ $((k+1)) -lt "${#HT[@]}" ]; then HEREDOC_END="${HT[$((k+1))]}"; fi; break ;;
          "$HD"*) wd=${wd#"$HD"}; wd=${wd#-}; HEREDOC_END="$wd"; break ;;
        esac
        k=$((k+1))
      done ;;
  esac

  LINE_COMPUTED=0
  case "$LINE" in *"$SUBST_OPEN"*|*'`'*|*"$BRACE_OPEN"*) LINE_COMPUTED=1 ;; esac

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
        # the text after a substitution belongs to the command that contained it
        [ "$PRE_CLASS" = "text" ] && INHERIT_TEXT=1
      fi ;;
    esac
    case "$SEG" in *"$DOLLAR"*) COMPUTED=1 ;; esac
    REDIRECT_IN=0
    case "$SEG" in *'<'*) REDIRECT_IN=1 ;; esac

    # ---- tokenize into shell words (quotes removed, nothing expanded)
    tokenize "$SEG"
    W=()
    for wd in "${WORDS[@]+"${WORDS[@]}"}"; do W+=("${wd:0:4096}"); done
    if [ "${#W[@]}" -eq 0 ]; then PREV_SEG="$SEG"; continue; fi

    # drop a trailing comment (a word that *starts* with #)
    N=0
    for wd in "${W[@]+"${W[@]}"}"; do
      case "$wd" in \#*) break ;; esac
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
        case "$d" in /*) EFFECTIVE_CWD="$d" ;; "~"*) EFFECTIVE_CWD="$HOMEDIR${d#\~}" ;; *) EFFECTIVE_CWD="$EFFECTIVE_CWD/$d" ;; esac
      fi
      LAST_CLASS="harmless"; PREV_SEG="$SEG"; continue
    fi

    # `echo terraform apply x | bash` (also behind sudo): a shell reading its script from a pipe
    if [ "$PIPED" -eq 1 ]; then
      shell_tok=""
      for wd in "${W[@]+"${W[@]}"}"; do base_of "$wd"; case "$R" in bash|sh|zsh|dash|ksh) shell_tok="$wd" ;; esac; done
      case "$shell_tok" in
        ?*)
          has_c=0
          for wd in "${W[@]+"${W[@]}"}"; do case "$wd" in -c|-*c*) has_c=1 ;; esac; done
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
      for wd in "${W[@]+"${W[@]}"}"; do
        case "$wd" in */*) base_of "$wd" ;; *) R=$wd ;; esac
        case " $SHELLS " in *" $R "*) HAS_SHELL=1 ;; esac
        case "$wd" in -c|--run|--command|--eval) HAS_SHELL=1 ;; esac   # a wrapper taking a command string
      done
      if [ "$FOUND" -lt 0 ] && [ "$HAS_SHELL" -eq 1 ]; then
        # Not found: re-split every word on whitespace so that a quoted "terraform apply x"
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
      # command as a whole mentions terraform (it got past the fast path), so refuse rather than
      # guess. `kubectl apply` and friends name their program plainly and are left alone.
      j=$i
      while [ $j -lt "$N" ]; do
        case "${W[$j]}" in
          apply|destroy)
            k=$((j-1))
            while [ $k -gt $i ]; do case "${W[$k]}" in -*) k=$((k-1)) ;; *) break ;; esac; done
            if [ $k -ge $i ]; then
              case "${W[$k]}" in
                "$DOLLAR"*) deny "whatbreaks: the program running ${W[$j]} is named through a variable (${W[$k]}), so it cannot be checked. Write it out plainly: terraform plan -out=tfplan, /whatbreaks:review tfplan, terraform apply tfplan." ;;
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
      *"$DOLLAR"*|*'`'*) deny "whatbreaks: the plan file name is computed at run time ($PLANFILE), so the reviewed file cannot be identified. Name the file plainly." ;;
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
    case "$PLANFILE" in /*) RESOLVED="$PLANFILE" ;; "~"*) RESOLVED="$HOMEDIR${PLANFILE#\~}" ;; *) RESOLVED="$BASE/$PLANFILE" ;; esac
    if [ ! -f "$RESOLVED" ]; then
      deny "whatbreaks: plan file $PLANFILE was not found (looked in $BASE), so it cannot have been reviewed. With terragrunt, a relative -out path lands in .terragrunt-cache; re-plan with an absolute -out path. $HOWTO"
    fi

    [ -z "$MARKER_DIR" ] && deny "whatbreaks: no plugin data directory is available (CLAUDE_PLUGIN_DATA is unset), so reviews cannot be verified. Update Claude Code, or turn the gate off with the apply_gate option."
    # The hash tool's output is read by gate_by_hash at the other end of a pipe, which
    # denies (exit 2, carried out of the pipeline) or returns 0 when this apply is allowed.
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$RESOLVED" | gate_by_hash
    elif command -v shasum >/dev/null 2>&1; then
      shasum -a 256 "$RESOLVED" | gate_by_hash
    elif command -v openssl >/dev/null 2>&1; then
      openssl dgst -sha256 -r "$RESOLVED" | gate_by_hash
    else
      deny "whatbreaks: cannot hash $PLANFILE (no sha256sum, shasum, or openssl on PATH), so the review cannot be verified. $HOWTO"
    fi
    rc=$?
    [ "$rc" -ne 0 ] && exit "$rc"
    PREV_SEG="$SEG"
  done
done

allow
