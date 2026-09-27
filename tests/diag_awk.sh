#!/bin/bash
# Temporary diagnostic: how does this platform's awk parse a many-line command?
eval "$(sed -n '/^json_scalar() {/,/^}/p' hooks/apply-gate.sh)"
cmd=$(yes 'true' | head -n 290; printf 'terraform apply tfplan')
payload=$(printf '%s' "$cmd" | python3 -c 'import json,sys; print(json.dumps({"cwd":"/tmp","tool_input":{"command":sys.stdin.read()}}))')
out=$(json_scalar "$payload" command)
printf '::notice title=awk diag 290::awk=%s in=%s out=%s lines=%s head=[%s] tail=[%s]\n' "$(awk --version 2>&1 | head -1 | tr -d '\n')" "${#payload}" "${#out}" "$(printf '%s' "$out" | wc -l | tr -d ' ')" "$(printf '%s' "$out" | head -c 30 | tr '\n' '~')" "$(printf '%s' "$out" | tail -c 60 | tr '\n' '~')"
cmd=$(yes 'true' | head -n 3; printf 'terraform apply tfplan')
payload=$(printf '%s' "$cmd" | python3 -c 'import json,sys; print(json.dumps({"cwd":"/tmp","tool_input":{"command":sys.stdin.read()}}))')
out=$(json_scalar "$payload" command)
printf '::notice title=awk diag 3::in=%s out=%s lines=%s all=[%s]\n' "${#payload}" "${#out}" "$(printf '%s' "$out" | wc -l | tr -d ' ')" "$(printf '%s' "$out" | tr '\n' '~')"
# and a version without gsub of newlines: does printf on a long string work?
printf '%s' "$payload" | LC_ALL=C awk 'BEGIN{RS="\001"} NR==1{ printf "::notice title=awk diag raw::len=%d nr=%d\n", length($0), NR; exit }'
printf '%s' "$payload" | LC_ALL=C awk 'NR==1{ printf "::notice title=awk diag default RS::len=%d\n", length($0); exit }'
