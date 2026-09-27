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
n_ok=0; n_bad=0; SLOWEST=0.00; SLOWEST_LABEL=""

PY=$(command -v python3)
run_hook() {
  # $1 = command, $2 = cwd -> prints "<decision> <seconds>". HOOK_PATH, when set, is the
  # PATH the runner and the hook see (see the restricted-PATH block).
  if [ -n "${HOOK_PATH:-}" ]; then
    printf '%s' "$1" | PATH="$HOOK_PATH" "$PY" "$ROOT/tests/run_hook.py" "$HOOK" "$2"
  else
    printf '%s' "$1" | "$PY" "$ROOT/tests/run_hook.py" "$HOOK" "$2"
  fi
}

expect() {
  # $1 = expected, $2 = command, $3 = cwd, $4 = label
  local got line
  line=$(run_hook "$2" "$3"); got=${line% *}; LAST_SECS=${line##* }
  if [ "$got" = "$1" ]; then n_ok=$((n_ok+1)); printf 'PASS  %-6s %5ss  %s\n' "$1" "$LAST_SECS" "$4"
  else
    n_bad=$((n_bad+1)); printf 'FAIL  want %s got %s  %s\n   cmd: %s\n' "$1" "$got" "$4" "${2:0:300}"
    # surface failures as annotations in GitHub Actions, where the log itself may be hard to reach
    [ -n "${GITHUB_ACTIONS:-}" ] && printf '::error title=apply-gate scenario::want %s got %s (%ss): %s -- %s\n' "$1" "$got" "$LAST_SECS" "$4" "$(printf '%s' "${2:0:200}" | tr '\n%' ' ~')"
  fi
  # the hook must stay far inside its 30 s timeout on every input (a timed-out hook allows)
  if [ "${LAST_SECS%.*}" -ge 8 ]; then n_bad=$((n_bad+1)); printf 'FAIL  %ss is too slow for the hook timeout  %s\n' "$LAST_SECS" "$4"; fi
  if [ "${LAST_SECS%.*}" -gt "${SLOWEST%.*}" ] || { [ "${LAST_SECS%.*}" -eq "${SLOWEST%.*}" ] && [ "${LAST_SECS#*.}" -gt "${SLOWEST#*.}" ]; }; then SLOWEST=$LAST_SECS; SLOWEST_LABEL=$4; fi
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
expect deny 'curl -o ok.tfplan example.invalid/p && terraform apply ok.tfplan' "$TMP/infra" "curl over reviewed file"
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
expect deny 'session-wrapper exec prod -- terraform apply tfplan' "$TMP/infra" "credential-helper style wrapper"
expect deny 'sudo -u deploy terraform apply tfplan' "$TMP/infra" "sudo -u wrapper"
expect deny 'timeout -s KILL 60 terraform apply tfplan' "$TMP/infra" "timeout with signal option"
expect deny 'mise exec -- terraform apply tfplan' "$TMP/infra" "mise exec wrapper"
expect deny 'docker run --rm -v /srv/infra:/w hashicorp/terraform apply tfplan' "$TMP/infra" "docker run image"
expect deny $'terraform \\\napply tfplan' "$TMP/infra" "backslash-newline before subcommand"
expect deny 'terraform_1.9.0 apply tfplan' "$TMP/infra" "versioned binary name"
expect deny 'opentofu apply tfplan' "$TMP/infra" "opentofu binary name"
expect deny 'terragrunt exec -- terraform apply -auto-approve' "$TMP/infra" "terragrunt exec"
expect deny 'terragrunt stack run apply' "$TMP/infra" "terragrunt stack run"
mkdir -p "$TMP/mono/infra"; cp "$TMP/infra/ok.tfplan" "$TMP/mono/tfplan"; printf 'unreviewed' > "$TMP/mono/infra/tfplan"
expect deny 'terraform -chdir=infra apply tfplan' "$TMP/mono" "chdir resolves inside the chdir directory"

# ===== second review round: wrappers handing a shell a string, unknown wrappers, image tags, writers, tricks
expect deny 'sudo bash -c "terraform apply tfplan"' "$TMP/infra" "sudo + bash -c"
expect deny "timeout 60 bash -c 'terraform apply -auto-approve'" "$TMP/infra" "timeout + bash -c"
expect deny 'nohup sh -c "terraform apply tfplan" &' "$TMP/infra" "nohup + sh -c"
expect deny 'nix-shell --run "terraform apply tfplan"' "$TMP/infra" "nix-shell --run"
expect deny 'uv run terraform apply tfplan' "$TMP/infra" "unknown wrapper (uv run)"
expect deny 'npx terraform apply tfplan' "$TMP/infra" "unknown wrapper (npx)"
expect deny 'some-unknown-tool exec -- terraform destroy -auto-approve' "$TMP/infra" "unknown wrapper + destroy"
expect deny 'docker run --rm hashicorp/terraform:1.9 apply tfplan' "$TMP/infra" "docker image tag"
expect deny 'docker run ghcr.io/opentofu/opentofu:1.8 apply tfplan' "$TMP/infra" "opentofu image tag"
expect deny 'aws s3 cp s3://b/x ok.tfplan && terraform apply ok.tfplan' "$TMP/infra" "aws s3 cp over reviewed file"
expect deny 'git checkout other -- ok.tfplan && terraform apply ok.tfplan' "$TMP/infra" "git checkout over reviewed file"
expect deny 'unzip -o plans.zip && terraform apply ok.tfplan' "$TMP/infra" "unknown earlier command before apply"
expect deny 'sudo cp tfplan ok.tfplan && terraform apply ok.tfplan' "$TMP/infra" "writer behind a wrapper"
expect deny "python3 -c \"open('ok.tfplan','wb').write(b'x')\" && terraform apply ok.tfplan" "$TMP/infra" "python writer before apply"
expect deny 'terr""aform apply tfplan' "$TMP/infra" "empty-quote split binary"
expect deny "terr'a'form apply tfplan" "$TMP/infra" "quoted-letter split binary"
expect deny "terraform \$'apply' tfplan" "$TMP/infra" "ANSI-C quoted subcommand"
expect deny 'terraform $(echo apply) tfplan' "$TMP/infra" "computed subcommand"
expect deny 'terraform ${x:-apply} tfplan' "$TMP/infra" "parameter-expansion subcommand"
expect deny 'terraform apply ok.tfplan#1' "$TMP/infra" "hash inside file name is not a comment"
expect deny $'cat <<EOF >/dev/null; terraform apply -auto-approve\nEOF' "$TMP/infra" "heredoc opened on the apply line"
expect deny 'echo "a<<b"; terraform apply -auto-approve' "$TMP/infra" "quoted << is not a heredoc"
expect deny 'case x in x) terraform apply tfplan;; esac' "$TMP/infra" "case statement"
expect deny 'terraform >log apply tfplan' "$TMP/infra" "redirect before subcommand"
expect deny 'tf apply tfplan' "$TMP/infra" "tf alias"
expect deny 'tfenv exec apply tfplan' "$TMP/infra" "tfenv exec"
expect deny 'terraform apply "$PLAN"' "$TMP/infra" "computed plan file name"
big=$(printf 'true; %.0s' $(seq 1 450))
expect deny "${big}terraform apply -auto-approve" "$TMP/infra" "segment-count backstop"

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
expect allow 'terraform -help apply' "$TMP/infra" "help before subcommand"
expect allow 'terraform show ok.tfplan > review.txt && terraform apply ok.tfplan' "$TMP/infra" "redirect to another file earlier"
expect allow 'echo "$(date): applying" >> log && terraform apply ok.tfplan' "$TMP/infra" "log append earlier"
expect allow 'touch .lock && terraform apply ok.tfplan' "$TMP/infra" "touch earlier"
expect allow 'terraform init && terraform apply ok.tfplan' "$TMP/infra" "init then reviewed apply"
expect allow 'export TF_LOG=INFO; terraform apply ok.tfplan' "$TMP/infra" "export then reviewed apply"
expect allow 'ls -la; terraform apply ok.tfplan' "$TMP/infra" "ls then reviewed apply"
expect allow 'if [ -f ok.tfplan ]; then terraform apply ok.tfplan; fi' "$TMP/infra" "if -f test then reviewed apply"
expect allow $'cat <<EOF > README.md\nrun terraform apply -auto-approve\nEOF\nterraform apply ok.tfplan' "$TMP/infra" "heredoc body then reviewed apply on next line"

# ===== third review round: false positives that must allow
expect allow 'terraform init 2>&1 | tee init.log && terraform apply ok.tfplan' "$TMP/infra" "2>&1 before reviewed apply"
expect allow 'terraform init >/dev/null 2>&1 && terraform apply ok.tfplan' "$TMP/infra" ">/dev/null 2>&1 before apply"
expect allow 'echo hi &> log && terraform apply ok.tfplan' "$TMP/infra" "&> before apply"
expect allow 'which terraform && terraform apply ok.tfplan' "$TMP/infra" "which terraform"
expect allow 'command -v terraform && terraform apply ok.tfplan' "$TMP/infra" "command -v terraform"
expect allow 'test -d terraform && terraform apply ok.tfplan' "$TMP/infra" "test -d terraform"
expect allow 'terraform -version && terraform apply ok.tfplan' "$TMP/infra" "-version then apply"
expect allow 'terraform state list && terraform apply ok.tfplan' "$TMP/infra" "state list then apply"
expect allow 'tfenv use 1.9.8 && terraform apply ok.tfplan' "$TMP/infra" "tfenv use then apply"
expect allow 'echo ${HOME} && terraform apply ok.tfplan' "$TMP/infra" "parameter expansion in echo"
expect allow 'export TF_VAR_x="${Y:-a}" && terraform apply ok.tfplan' "$TMP/infra" "parameter expansion in export"
expect allow 'echo "$(date): terraform apply starting" && terraform apply ok.tfplan' "$TMP/infra" "substitution inside echo text"
expect allow 'echo "$(date) - terraform apply" >> log; terraform apply ok.tfplan' "$TMP/infra" "substitution in echo with log append"
expect allow 'for i in 1; do terraform apply ok.tfplan; done' "$TMP/infra" "for loop over reviewed plan"
expect allow 'gh pr create --title "terraform apply prod" --body "x"' "$TMP/infra" "quoted text argument to gh"
expect allow 'aws sns publish --message "terraform apply prod finished"' "$TMP/infra" "quoted text argument to aws"
expect allow 'set -o pipefail && terraform init 2>&1 | tee init.log && terraform apply ok.tfplan' "$TMP/infra" "pipefail + init + apply"

# ===== third review round: deliberate bypasses that must deny
expect deny 'docker run --entrypoint terraform myorg/tfimage:1.9 apply tfplan' "$TMP/infra" "entrypoint with image before subcommand"
expect deny 'echo terraform apply tfplan | sudo bash' "$TMP/infra" "piped shell behind sudo"
expect deny $'echo "a<<b"\nterraform apply -auto-approve' "$TMP/infra" "quoted << then apply on next line"
expect deny $'ls\ntf apply tfplan' "$TMP/infra" "tf alias on second line"
expect deny '(tf apply tfplan)' "$TMP/infra" "tf alias in subshell"
expect deny "\$'terraform' apply tfplan" "$TMP/infra" "ANSI-C quoted binary"
expect deny 'git checkout other && terraform apply ok.tfplan' "$TMP/infra" "git checkout before apply"
expect deny 'git stash pop && terraform apply ok.tfplan' "$TMP/infra" "git stash pop before apply"
out=$(printf '{"cwd":"%s","tool_input":{"command":"terraform apply ok.tfplan"}}' "$TMP/infra" | env -u HOME bash "$HOOK" 2>/dev/null); rc=$?
if [ "$rc" -eq 0 ] && [ -z "$out" ]; then n_ok=$((n_ok+1)); echo "PASS  allow  HOME unset does not crash"; else n_bad=$((n_bad+1)); echo "FAIL  HOME unset: rc=$rc out=$out"; fi
out=$(printf '{"cwd":"%s","tool_input":{"command":"terraform apply ok.tfplan"}}' "$TMP/infra" | env -u CLAUDE_PLUGIN_DATA bash "$HOOK" 2>/dev/null); rc=$?
if [ "$rc" -eq 2 ]; then n_ok=$((n_ok+1)); echo "PASS  deny   CLAUDE_PLUGIN_DATA unset fails closed"; else n_bad=$((n_bad+1)); echo "FAIL  CLAUDE_PLUGIN_DATA unset: rc=$rc"; fi

# ===== fourth round: variable-named binaries, quoting handled by the built-in tokenizer, size guards
expect deny 'TF=terraform; $TF apply tfplan' "$TMP/infra" "binary named through a variable"
expect deny 'export TF=terraform && sudo "$TF" destroy' "$TMP/infra" "quoted variable binary behind sudo"
expect deny 'TF=terraform; $TF -chdir=envs/prod apply tfplan' "$TMP/infra" "variable binary with a global flag"
expect allow 'kubectl apply -f x.yaml && terraform validate' "$TMP/infra" "kubectl apply beside terraform validate"
expect allow 'sudo -u deploy kubectl apply -f x.yaml && terraform plan' "$TMP/infra" "variable elsewhere, kubectl apply named plainly"
expect allow "terraform apply 'ok.tfplan'" "$TMP/infra" "single-quoted reviewed plan"
expect allow 'terraform apply ok\.tfplan' "$TMP/infra" "backslash-escaped reviewed plan"
expect allow 'terraform apply "ok"".tfplan"' "$TMP/infra" "adjacent quoted pieces"
expect allow $'terraform apply $\'ok.tfplan\'' "$TMP/infra" "ANSI-C quoted reviewed plan"
expect deny 'terraform apply "tfplan' "$TMP/infra" "unterminated quote still gated"
expect deny "terraform apply tfplan '" "$TMP/infra" "trailing unterminated quote still gated"
expect deny 'terraform ap""ply tfplan' "$TMP/infra" "subcommand split by empty quotes"
expect deny 'nix run nixpkgs#terraform -- apply tfplan' "$TMP/infra" "flake attribute naming the binary"
expect deny 'devbox run --command "terraform apply tfplan"' "$TMP/infra" "unknown wrapper with a command-string flag"
expect allow 'gh pr create --title "terraform apply prod" --body x && terraform plan' "$TMP/infra" "title string with a plain flag stays text"
expect deny 'nix shell nixpkgs#opentofu -c tofu apply tfplan' "$TMP/infra" "nix shell then tofu apply"
# size guards: a command the hook could not finish parsing in time must deny, not time out (a timed-out hook allows)
expect deny "$(yes 'true;' | head -n 400 | tr -d '\n') terraform \$(echo ap)ply tfplan" "$TMP/infra" "hundreds of parts, computed subcommand"
expect deny "echo $(yes '"a"' | head -n 1400 | tr '\n' ' ')&& terraform \$(echo ap)ply tfplan" "$TMP/infra" "thousands of quoted words, computed subcommand"
expect deny "echo $(yes 'a' | head -n 3900 | tr '\n' ' ')&& terraform apply tfplan" "$TMP/infra" "thousands of plain words under the cap, unreviewed apply"
expect deny "$(printf '/'; head -c 4000 /dev/zero | tr '\0' a; printf '/terraform apply tfplan')" "$TMP/infra" "very long path to the binary"
expect deny "$(yes 'true' | head -n 2100)
terraform \$(echo ap)ply tfplan" "$TMP/infra" "thousands of lines, computed subcommand"
expect deny "echo $(head -c 140000 /dev/zero | tr '\0' a) && terraform \$(echo ap)ply tfplan" "$TMP/infra" "over the byte cap, computed subcommand"
expect allow "echo $(head -c 120000 /dev/zero | tr '\0' a) && terraform apply ok.tfplan" "$TMP/infra" "long but simple line before a reviewed apply"
expect allow "$(printf "cat > x.tf <<'EOF'\n"; yes 'resource "aws_instance" "x" { ami = "abc" ; instance_type = "t3.micro" }' | head -n 1500; printf 'EOF\nterraform fmt')" "$TMP/infra" "large heredoc body then fmt"
expect allow "$(yes 'true &&' | head -n 100 | tr '\n' ' ') terraform apply ok.tfplan" "$TMP/infra" "a hundred harmless parts then reviewed apply"

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
  n_bad=$((n_bad+1)); echo "FAIL  approve accepted an unreviewed plan"
else n_ok=$((n_ok+1)); echo "PASS  approve refuses unreviewed plan"; fi

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
  n_ok=$((n_ok+1)); echo "PASS  deny output is valid JSON"
else n_bad=$((n_bad+1)); echo "FAIL  deny output is not valid JSON: $out"; fi

# ===== with nothing on PATH but bash and a hash tool, every decision must be the same:
# the hook depends on no other program
FB=$(mktemp -d)
for b in bash sha256sum shasum; do p=$(command -v "$b" 2>/dev/null) && ln -s "$p" "$FB/$b"; done
cp "$ROOT/evals/clean-plan/resources/plan.json" "$TMP/infra/ok2.tfplan"
python3 "$ANALYZER" "$TMP/infra/ok2.tfplan" --plan-file "$TMP/infra/ok2.tfplan" --marker-dir "$CLAUDE_PLUGIN_DATA/reviews" >/dev/null
python3 "$ANALYZER" "$ROOT/evals/destroy-plan/resources/plan.json" --plan-file "$TMP/infra/block.tfplan" --marker-dir "$CLAUDE_PLUGIN_DATA/reviews" >/dev/null
HOOK_PATH="$FB"
expect deny  'echo "x"; terraform apply -auto-approve' "$TMP" "bare PATH: auto-approve with quotes in the command"
expect allow 'ls -la' "$TMP" "bare PATH: unrelated command"
expect allow 'terraform apply ok2.tfplan' "$TMP/infra" "bare PATH: reviewed plan read from the marker"
expect deny  'terraform apply tfplan' "$TMP/infra" "bare PATH: unreviewed plan"
expect allow $'cat > README.md <<EOF\nterraform apply -auto-approve\nEOF\nterraform apply ok2.tfplan' "$TMP/infra" "bare PATH: newlines and a heredoc body"
expect deny  $'terraform apply\ttfplan' "$TMP/infra" "bare PATH: tab between words"
expect deny  'terraform apply we"ird.tfplan' "$TMP/infra" "bare PATH: quote inside the command"
expect deny  'terraform apply back\\slash.tfplan' "$TMP/infra" "bare PATH: backslashes inside the command"
expect deny  'terraform apply block.tfplan' "$TMP/infra" "bare PATH: BLOCK verdict read from the marker"
python3 "$APPROVE" "$TMP/infra/block.tfplan" --marker-dir "$CLAUDE_PLUGIN_DATA/reviews" --reason "test" >/dev/null
expect allow 'terraform apply block.tfplan' "$TMP/infra" "bare PATH: approval read from the marker"
python3 "$APPROVE" "$TMP/infra/block.tfplan" --marker-dir "$CLAUDE_PLUGIN_DATA/reviews" --revoke >/dev/null
expect deny  "echo $(yes 'a' | head -n 3900 | tr '\n' ' ')&& terraform apply tfplan" "$TMP/infra" "bare PATH: thousands of plain words under the cap"
expect deny  "$(yes 'true' | head -n 290; printf 'terraform apply tfplan')" "$TMP/infra" "bare PATH: hundreds of lines"
unset HOOK_PATH
rm -rf "$FB"

echo
echo "slowest scenario: ${SLOWEST}s (${SLOWEST_LABEL})"
[ -n "${GITHUB_ACTIONS:-}" ] && printf '::notice title=apply-gate timing::%s passed, %s failed; slowest %ss (%s); bash %s\n' "$n_ok" "$n_bad" "$SLOWEST" "$SLOWEST_LABEL" "$BASH_VERSION"
echo
echo "$n_ok passed, $n_bad failed"
[ "$n_bad" -eq 0 ]
