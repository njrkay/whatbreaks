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
  out=$(printf '{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","cwd":%s,"tool_input":{"command":%s}}' \
        "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$cwd")" \
        "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$cmd")" | bash "$HOOK")
  case "$out" in *'"deny"'*) echo deny ;; "") echo allow ;; *) echo "weird:$out" ;; esac
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

# --- gate can be switched off by userConfig
CLAUDE_PLUGIN_OPTION_APPLY_GATE=false
export CLAUDE_PLUGIN_OPTION_APPLY_GATE
expect allow 'terraform apply -auto-approve' "$TMP/infra" "gate disabled via option"
unset CLAUDE_PLUGIN_OPTION_APPLY_GATE

# --- output is valid JSON when denying
out=$(printf '{"cwd":"%s","tool_input":{"command":"terraform apply -auto-approve"}}' "$TMP" | bash "$HOOK")
if printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["hookSpecificOutput"]["permissionDecision"]=="deny"'; then
  PASS=$((PASS+1)); echo "PASS  deny output is valid JSON"
else FAIL=$((FAIL+1)); echo "FAIL  deny output is not valid JSON: $out"; fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
