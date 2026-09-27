#!/usr/bin/env bash
# Exercise hooks/apply-gate.sh with synthetic PreToolUse payloads.
# Usage: tests/test_hook.sh   (exit 0 when every expectation holds)
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
HOOK="$ROOT/hooks/apply-gate.sh"
ANALYZER="$ROOT/skills/review/scripts/analyze_plan.py"
APPROVE="$ROOT/skills/approve/scripts/approve_plan.py"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export CLAUDE_PLUGIN_DATA="$TMP/data"
export CLAUDE_PLUGIN_ROOT="$ROOT"
unset CLAUDE_PLUGIN_OPTION_APPLY_GATE
mkdir -p "$TMP/infra"
PASS=0; FAIL=0

run_hook() {
  # $1 = command, $2 = cwd -> prints "deny" or "allow"
  local cmd=$1 cwd=$2 out
  local rc
  out=$(printf '{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","cwd":%s,"tool_input":{"command":%s}}' \
        "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$cwd")" \
        "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$cmd")" | bash "$HOOK" 2>/dev/null); rc=$?
  if [ -n "$out" ]; then
    if ! printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["hookSpecificOutput"]["permissionDecision"]=="deny"' 2>/dev/null; then
      echo "invalid-json:$out"; return
    fi
    [ "$rc" -eq 2 ] && echo deny || echo "deny-but-exit-$rc"
  else
    [ "$rc" -eq 0 ] && echo allow || echo "allow-but-exit-$rc"
  fi
}

expect() {
  # $1 = expected, $2 = command, $3 = cwd, $4 = label
  local got
  got=$(run_hook "$2" "$3")
  if [ "$got" = "$1" ]; then PASS=$((PASS+1)); printf 'PASS  %-6s %s\n' "$1" "$4"
  else FAIL=$((FAIL+1)); printf 'FAIL  want %s got %s  %s\n   cmd: %s\n' "$1" "$got" "$4" "$2"; fi
}

# --- unrelated / read-only commands pass through
expect allow 'ls -la' "$TMP" "unrelated command"
expect allow 'terraform plan -out=tfplan' "$TMP/infra" "plan is allowed"
expect allow 'terraform init && terraform validate' "$TMP/infra" "init/validate allowed"
expect allow 'terraform show -json tfplan > plan.json' "$TMP/infra" "show allowed"
expect allow 'grep -r "terraform apply" docs/' "$TMP" "mention inside grep args is not a terraform invocation"
expect allow 'echo terraform apply' "$TMP" "echo mention allowed"
expect allow 'tofu fmt -check' "$TMP" "tofu fmt allowed"

# --- unreviewed applies are denied
expect deny 'terraform apply' "$TMP/infra" "bare apply (no plan file)"
expect deny 'terraform apply -auto-approve' "$TMP/infra" "auto-approve without plan"
expect deny 'tofu apply -auto-approve' "$TMP/infra" "tofu auto-approve"
expect deny 'yes | terraform apply' "$TMP/infra" "piped yes"
expect deny 'terraform apply < answers.txt' "$TMP/infra" "stdin redirect"
expect deny 'TF_CLI_ARGS_apply="-auto-approve" terraform apply' "$TMP/infra" "TF_CLI_ARGS back door"
expect deny 'terraform destroy' "$TMP/infra" "destroy"
expect deny 'terraform destroy -auto-approve -target=aws_instance.x' "$TMP/infra" "destroy targeted"
expect deny 'terraform apply -destroy -auto-approve' "$TMP/infra" "apply -destroy"
expect deny 'terraform plan -out=tfplan && terraform apply tfplan' "$TMP/infra" "plan+apply in one command"
expect deny 'cd infra && terraform apply tfplan' "$TMP" "apply of missing plan file"
expect deny 'terragrunt run-all apply --terragrunt-non-interactive' "$TMP/infra" "terragrunt run-all"
expect deny 'terragrunt run --all apply' "$TMP/infra" "terragrunt run --all"
expect deny 'sudo -E terraform apply -auto-approve' "$TMP/infra" "sudo wrapper"
expect deny 'timeout 600 terraform apply -var-file=prod.tfvars -auto-approve' "$TMP/infra" "timeout wrapper + var-file"
expect deny 'terraform -chdir=infra apply -auto-approve' "$TMP" "chdir auto-approve"

# --- a reviewed plan file (verdict OK) is allowed
printf 'fake-binary-plan-ok' > "$TMP/infra/ok.tfplan"
python3 "$ANALYZER" "$ROOT/evals/clean-plan/resources/plan.json" --plan-file "$TMP/infra/ok.tfplan" \
  --marker-dir "$CLAUDE_PLUGIN_DATA/reviews" >/dev/null
expect allow 'terraform apply ok.tfplan' "$TMP/infra" "reviewed OK plan"
expect allow 'terraform apply -auto-approve ok.tfplan' "$TMP/infra" "reviewed OK plan with -auto-approve"
expect allow 'terraform apply -var region=eu-west-1 ok.tfplan' "$TMP/infra" "value-taking flag before plan file"
expect allow 'cd infra && terraform apply ok.tfplan' "$TMP" "cd then apply reviewed plan"
expect allow 'terraform -chdir=infra apply ok.tfplan' "$TMP" "chdir apply reviewed plan"
expect allow "terraform apply $TMP/infra/ok.tfplan" "$TMP" "absolute path"

# ===== bypasses found in review: every one of these must deny while ok.tfplan is reviewed and tfplan is not
printf 'unreviewed' > "$TMP/infra/tfplan"
expect deny 'terraform apply ok.tfplan && terraform apply tfplan' "$TMP/infra" "reviewed then unreviewed in one line"
expect deny 'terraform apply ok.tfplan; terraform destroy -auto-approve' "$TMP/infra" "reviewed then destroy"
expect deny 'terraform plan -out=ok.tfplan && terraform apply ok.tfplan' "$TMP/infra" "re-plan into reviewed filename"
expect deny 'cp tfplan ok.tfplan && terraform apply ok.tfplan' "$TMP/infra" "cp over reviewed file"
expect deny 'curl -o ok.tfplan https://example.invalid/p && terraform apply ok.tfplan' "$TMP/infra" "curl over reviewed file"
expect deny 'cat tfplan > ok.tfplan; terraform apply ok.tfplan' "$TMP/infra" "redirect over reviewed file"
expect deny '"terraform" apply tfplan' "$TMP/infra" "quoted binary"
expect deny '\terraform apply tfplan' "$TMP/infra" "backslash-escaped binary"
expect deny 'terraform "apply" tfplan' "$TMP/infra" "quoted subcommand"
expect deny 'terraform ap\ply tfplan' "$TMP/infra" "backslash inside subcommand"
expect deny '(terraform apply tfplan)' "$TMP/infra" "subshell"
expect deny '{ terraform apply tfplan; }' "$TMP/infra" "brace group"
expect deny 'if true; then terraform apply tfplan; fi' "$TMP/infra" "if/then"
expect deny 'for f in tfplan; do terraform apply "$f"; done' "$TMP/infra" "for loop"
expect deny 'AWS_PROFILE="my prod" terraform apply -auto-approve' "$TMP/infra" "env assignment with space"
expect deny 'terraform -chdir="dir with space" destroy' "$TMP/infra" "chdir with space then destroy"
expect deny 'bash -c "terraform apply tfplan"' "$TMP/infra" "bash -c"
expect deny "sh -lc 'terraform apply -auto-approve'" "$TMP/infra" "sh -lc"
expect deny 'eval terraform apply tfplan' "$TMP/infra" "eval"
expect deny 'echo terraform apply tfplan | bash' "$TMP/infra" "echo | bash"
expect deny 'echo tfplan | xargs terraform apply' "$TMP/infra" "xargs"
expect deny 'find . -name tfplan -exec terraform apply {} \;' "$TMP/infra" "find -exec"
expect deny 'ssh prod "terraform apply -auto-approve"' "$TMP/infra" "ssh remote apply"
expect deny 'aws-vault exec prod -- terraform apply tfplan' "$TMP/infra" "aws-vault wrapper"
expect deny 'sudo -u deploy terraform apply tfplan' "$TMP/infra" "sudo -u wrapper"
expect deny 'timeout -s KILL 60 terraform apply tfplan' "$TMP/infra" "timeout with signal option"
expect deny 'mise exec -- terraform apply tfplan' "$TMP/infra" "mise exec wrapper"
expect deny 'docker run --rm -v "$PWD:/w" hashicorp/terraform apply tfplan' "$TMP/infra" "docker run image"
expect deny $'terraform \\\napply tfplan' "$TMP/infra" "backslash-newline before subcommand"
expect deny 'terraform_1.9.0 apply tfplan' "$TMP/infra" "versioned binary name"
expect deny 'opentofu apply tfplan' "$TMP/infra" "opentofu binary name"
expect deny 'terragrunt exec -- terraform apply -auto-approve' "$TMP/infra" "terragrunt exec"
expect deny 'terragrunt stack run apply' "$TMP/infra" "terragrunt stack run"
mkdir -p "$TMP/mono/infra"; cp "$TMP/infra/ok.tfplan" "$TMP/mono/tfplan"; printf 'unreviewed' > "$TMP/mono/infra/tfplan"
expect deny 'terraform -chdir=infra apply tfplan' "$TMP/mono" "chdir resolves inside the chdir directory"

# ===== false positives the tokenizer must NOT produce
expect allow $'terraform apply \\\n  ok.tfplan' "$TMP/infra" "backslash-newline continuation before plan file"
mkdir -p "$TMP/sp ace" && cp "$TMP/infra/ok.tfplan" "$TMP/sp ace/ok.tfplan"
expect allow "cd 'sp ace' && terraform apply ok.tfplan" "$TMP" "cd into directory with a space"
cp "$TMP/infra/ok.tfplan" "$TMP/infra/my plan.tfplan"
expect allow 'terraform apply "my plan.tfplan"' "$TMP/infra" "plan file name with a space"
expect allow 'terraform apply ok.tfplan > apply.log' "$TMP/infra" "redirect in the apply segment itself"
expect allow 'terraform apply ok.tfplan 2>&1 | tee apply.log' "$TMP/infra" "tee after apply"
expect allow 'AWS_PROFILE="my prod" terraform apply ok.tfplan' "$TMP/infra" "env assignment with space, reviewed plan"
expect allow $'cat > Makefile <<EOF\napply:\n\tterraform apply -auto-approve\nEOF' "$TMP/infra" "heredoc body mentioning apply"
expect allow 'terraform apply -help' "$TMP/infra" "apply -help"
expect allow 'terraform apply ok.tfplan; terraform output' "$TMP/infra" "reviewed apply then output"
out=$(printf '{"cwd":"%s","tool_input":{"command":"terraform apply ok.tfplan"}}' "$TMP/infra" | env -u HOME bash "$HOOK" 2>/dev/null); rc=$?
if [ "$rc" -eq 0 ] && [ -z "$out" ]; then PASS=$((PASS+1)); echo "PASS  allow  HOME unset does not crash"; else FAIL=$((FAIL+1)); echo "FAIL  HOME unset: rc=$rc out=$out"; fi
out=$(printf '{"cwd":"%s","tool_input":{"command":"terraform apply ok.tfplan"}}' "$TMP/infra" | env -u CLAUDE_PLUGIN_DATA bash "$HOOK" 2>/dev/null); rc=$?
if [ "$rc" -eq 2 ]; then PASS=$((PASS+1)); echo "PASS  deny   CLAUDE_PLUGIN_DATA unset fails closed"; else FAIL=$((FAIL+1)); echo "FAIL  CLAUDE_PLUGIN_DATA unset: rc=$rc"; fi

# --- modifying the plan file invalidates the review
printf 'fake-binary-plan-ok-modified' > "$TMP/infra/ok.tfplan"
expect deny 'terraform apply ok.tfplan' "$TMP/infra" "plan file changed after review"

# --- BLOCK verdict needs explicit approval
printf 'fake-binary-plan-block' > "$TMP/infra/block.tfplan"
python3 "$ANALYZER" "$ROOT/evals/destroy-plan/resources/plan.json" --plan-file "$TMP/infra/block.tfplan" \
  --marker-dir "$CLAUDE_PLUGIN_DATA/reviews" >/dev/null
expect deny 'terraform apply block.tfplan' "$TMP/infra" "BLOCK verdict without approval"
python3 "$APPROVE" "$TMP/infra/block.tfplan" --marker-dir "$CLAUDE_PLUGIN_DATA/reviews" --reason "test" >/dev/null
expect allow 'terraform apply block.tfplan' "$TMP/infra" "BLOCK verdict after approval"
python3 "$APPROVE" "$TMP/infra/block.tfplan" --marker-dir "$CLAUDE_PLUGIN_DATA/reviews" --revoke >/dev/null
expect deny 'terraform apply block.tfplan' "$TMP/infra" "approval revoked"

# --- approve refuses unreviewed plans unless forced
printf 'never-reviewed' > "$TMP/infra/new.tfplan"
if python3 "$APPROVE" "$TMP/infra/new.tfplan" --marker-dir "$CLAUDE_PLUGIN_DATA/reviews" >/dev/null 2>&1; then
  FAIL=$((FAIL+1)); echo "FAIL  approve accepted an unreviewed plan"
else PASS=$((PASS+1)); echo "PASS  approve refuses unreviewed plan"; fi

# --- hostile plan file names must still deny with valid JSON (an invalid JSON deny would be treated as non-blocking)
printf 'x' > "$TMP/infra/we\"ird.tfplan"
expect deny 'terraform apply we"ird.tfplan' "$TMP/infra" "double quote in plan file name"
printf 'x' > "$TMP/infra/back\\slash.tfplan"
expect deny 'terraform apply back\\slash.tfplan' "$TMP/infra" "backslash in plan file name"
expect deny "terraform apply \$(printf 'a\\tb').tfplan" "$TMP/infra" "control characters via substitution"
expect deny 'terraform apply -auto-approve "$(cat /etc/hostname)"' "$TMP/infra" "command substitution as plan file"

# --- gate can be switched off by userConfig
CLAUDE_PLUGIN_OPTION_APPLY_GATE=false
export CLAUDE_PLUGIN_OPTION_APPLY_GATE
expect allow 'terraform apply -auto-approve' "$TMP/infra" "gate disabled via option"
unset CLAUDE_PLUGIN_OPTION_APPLY_GATE

# --- output is valid JSON when denying
out=$(printf '{"cwd":"%s","tool_input":{"command":"terraform apply -auto-approve"}}' "$TMP" | bash "$HOOK" 2>/dev/null)
if printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["hookSpecificOutput"]["permissionDecision"]=="deny"'; then
  PASS=$((PASS+1)); echo "PASS  deny output is valid JSON"
else FAIL=$((FAIL+1)); echo "FAIL  deny output is not valid JSON: $out"; fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
