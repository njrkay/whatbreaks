#!/bin/bash
# Temporary diagnostic: the full parser on this platform's awk
eval "$(sed -n '/^json_scalar() {/,/^}/p' hooks/apply-gate.sh)"
j='{"cwd": "/t", "cmd": "a\nb\\c\"d\\\\e\tf"}'
printf '::notice title=full::%s\n' "$(json_scalar "$j" cmd | od -c | head -2 | tr '\n' ' ')"
cmd=$(yes 'true' | head -n 290; printf 'terraform apply tfplan')
payload=$(printf '%s' "$cmd" | python3 -c 'import json,sys; print(json.dumps({"cwd":"/tmp","tool_input":{"command":sys.stdin.read()}}))')
out=$(json_scalar "$payload" command)
printf '::notice title=290 lines::out=%s lines=%s tail=[%s]\n' "${#out}" "$(printf '%s' "$out" | wc -l | tr -d ' ')" "$(printf '%s' "$out" | tail -c 40 | tr '\n' '~')"
