# What Breaks

**Risk review for Terraform and OpenTofu plans, before you apply.**

`whatbreaks` reads the JSON that `terraform show -json <planfile>` produces and tells you what the
apply would actually do to your infrastructure: what gets destroyed or replaced (and whether that
loses data), what becomes reachable from the internet, which safety mechanisms are switched off,
and which IAM changes hand out more power than they should. Every finding is ranked by severity
and comes with a concrete fix. In Claude Code and Cowork, an apply gate refuses to run
`terraform apply` until the exact plan file has been reviewed.

It works for any provider. AWS, Google Cloud, Azure, Kubernetes, and Helm resources are
catalogued; unknown providers are rated by heuristics. Terragrunt and OpenTofu are supported
wherever Terraform is.

> Terraform and OpenTofu are trademarks of their respective owners; this plugin is an independent
> project and is not affiliated with HashiCorp, the OpenTofu project, or Anthropic.

## What it does

| Component | Where it runs | What it does |
|---|---|---|
| `/whatbreaks:review [plan-file\|plan.json]` (skill) | chat, Cowork, Claude Code | Renders the plan to JSON if needed, runs the deterministic analyzer, then writes a verdict-first review: what breaks, the fix for each finding, what else changes, what to check before applying. Also triggers on its own when you share a plan or ask whether one is safe. |
| `/whatbreaks:approve <plan-file>` (skill) | Cowork, Claude Code | Records your explicit decision to apply a plan whose verdict was **BLOCK**. Only you can invoke it; Claude will not run it on its own. `--revoke` takes it back. |
| Apply gate (hook, `hooks/apply-gate.sh`) | Cowork, Claude Code | A `PreToolUse` hook on the Bash tool. Denies `terraform`/`tofu`/`terragrunt` `apply` and `destroy` unless the plan file named in the command has a review marker (or an approval after BLOCK). Also denies `-auto-approve` without a saved plan, `plan && apply` in one command, piped/env-injected approvals, and `terragrunt run-all apply`. |
| `scripts/analyze_plan.py` | everywhere Python 3.8+ runs | The rule engine. Standard library only, no network. Usable on its own and in CI (`--exit-code`). |
| `scripts/redact_plan.py` | everywhere | Strips sensitive values and bulky sections from a plan JSON so it can be shared or uploaded to chat. |

Verdicts: **BLOCK** (any critical finding), **WARN** (any high), **REVIEW** (any medium), **OK**.

### What the analyzer looks for

- **Destructive changes** — every delete and replace, rated by what the resource type holds
  (data → CRITICAL, live endpoint/control → HIGH, unknown → MEDIUM, stateless → LOW), with
  Terraform's own reason decoded: ForceNew attribute, taint, `-replace`, a resource removed from
  configuration, a rename without a `moved` block, a `count`/`for_each` index shift, a removed
  module. Whole-plan destroy detection. Missing final snapshots and `force_destroy` are called out.
- **Safety mechanisms weakened** — `deletion_protection`, `skip_final_snapshot`, `force_destroy`,
  backup retention, point-in-time recovery, S3 versioning and public-access-block settings,
  encryption flags, logging/audit controls, KMS deletion window, permissions boundaries, minimum TLS.
- **Network exposure** — security groups, `aws_vpc_security_group_ingress_rule`, GCP firewalls,
  Azure NSGs and NSG rules gaining `0.0.0.0/0`, `::/0`, or `*` sources (admin/database ports and
  all-ports rules are CRITICAL, web ports LOW); public database toggles, public bucket ACLs, Lambda
  URLs without auth, Cloud SQL authorized networks, Azure database firewall rules, internet-facing
  load balancers.
- **IAM widening** — new `Action: *` / `Resource: *` statements, `NotAction` allows, service-wide
  wildcards, `iam:PassRole` on `*`, privilege-escalation actions, trust policies assumable by
  anyone or by new accounts, GitHub OIDC trusts without a `sub` condition, public resource
  policies, admin managed-policy attachments, static credentials, GCP `allUsers`/`roles/owner`
  bindings and authoritative IAM policies, Azure `Owner`/`Contributor` at subscription scope.
  Pre-existing issues are reported separately from ones this plan introduces.
- **Plan-level** — errored plans, partial plans (`-target`), large blast radius, drift.

Full rule tables: [`skills/review/references/reading-a-plan.md`](skills/review/references/reading-a-plan.md)
and [`resource-catalog.md`](skills/review/references/resource-catalog.md). Fixes:
[`fix-playbook.md`](skills/review/references/fix-playbook.md).

## Install

From the directory in Claude: **Customize → Plugins**, search for *What Breaks*. From Claude Code:

```
/plugin install whatbreaks@claude-plugins-community
```

Or straight from this repository during development:

```bash
claude --plugin-dir ./whatbreaks
```

Requirements: Python 3.8+ on the machine where the review runs (Claude's chat sandbox has it), and
`terraform`/`tofu` on `PATH` if you want Claude to produce the plan for you. The apply gate needs
Claude Code or Cowork; it has no effect in chat.

## Use it

**In chat (claude.ai):** attach the output of `terraform show -json tfplan` (run
`scripts/redact_plan.py --mask-accounts` on it first if it contains anything you would not paste
into a ticket), or paste the plan text, and ask.

**In Claude Code / Cowork:**

```
/whatbreaks:review               # plans the current directory and reviews the result
/whatbreaks:review tfplan        # reviews a saved plan file
/whatbreaks:review plan.json     # reviews an already-rendered JSON plan
```

Then `terraform apply tfplan` is allowed for that file if the verdict was OK/REVIEW/WARN. For BLOCK,
read the findings and, if you still want to proceed, run `/whatbreaks:approve tfplan` and say so
in your own words.

**Example prompts**

1. "Here's my plan JSON — is it safe to apply?"
2. "What breaks if I apply this? It says 2 to destroy and I only changed a tag."
3. "Review tfplan before I apply it to prod."
4. "Why does this plan want to replace the RDS instance, and how do I stop it?"
5. "Which of these security group changes open something to the internet?"

**Standalone / CI**

```bash
terraform plan -out=tfplan && terraform show -json tfplan > plan.json
python3 skills/review/scripts/analyze_plan.py plan.json --exit-code     # exit 2 on BLOCK, 1 on WARN
python3 skills/review/scripts/analyze_plan.py plan.json --format json  # machine-readable findings
```

## How the apply gate works, and its limits

The gate is a speed bump that makes the safe workflow the only convenient one, not a security
boundary.

- It keys reviews on the SHA-256 of the plan file. Re-running `terraform plan` produces a new file
  that needs its own review; editing the file invalidates the review.
- Markers live in `${CLAUDE_PLUGIN_DATA}/reviews` (Claude Code's per-plugin data directory,
  `~/.claude/plugins/data/<id>/`). Delete that directory to forget all reviews.
- A denial works even in `--dangerously-skip-permissions` / bypass mode, because hook decisions are
  separate from the permission system.
- It only sees the command string. It looks through `cd`, `sudo`, `env`, `timeout`, `&&`/`;`/`|`
  chains and `-chdir`, and it treats `TF_CLI_ARGS`, `yes |`, and stdin redirection as auto-approve.
  It cannot see inside a script file or an alias (`./deploy.sh`, `make apply`, `t=terraform; $t apply`).
  If your team applies through a wrapper, add a `PreToolUse` rule for it or rely on the review skill.
- Turn it off with the plugin's **apply_gate** option (`/plugin configure whatbreaks@…` in Claude
  Code) rather than by editing the hook.

## What the plugin reads, runs, and sends

- **Reads:** the plan JSON you point it at (or that it renders with `terraform show -json`), the
  plan file named in an `apply` command (to hash it), and its own marker files. In chat, the skill
  folder including `analyze_plan.py` is copied into Claude's code-execution sandbox and runs there.
- **Runs:** `terraform`/`tofu`/`terragrunt` `plan` and `show` (only when you ask for a review without
  a plan file), the bundled Python scripts, and the bash hook. Nothing is installed; there are no
  package launchers, no dependencies, no compiled code.
- **Writes:** a rendered `<plan>.json` next to your plan file when it has to render one, and JSON
  marker files under `${CLAUDE_PLUGIN_DATA}/reviews`.
- **Sends:** nothing. No network access of any kind. Plan contents go only where you send them
  (to Claude, as part of the conversation you are already having).
- **Sensitive values:** never printed. The analyzer honours the plan's `*_sensitive` maps;
  `redact_plan.py` also masks values under secret-looking attribute names and can mask account IDs.

## Test it

```bash
python3 tests/test_fixtures.py   # 15 fixture plans with expected verdicts and findings
bash tests/test_hook.sh          # 36 apply-gate scenarios
claude plugin validate .         # manifest and component checks
claude plugin eval . --allow-tools "Bash(python3 *)"   # behavioural evals (uses your Claude credentials)
```

Last verified: the 7 smoke-tagged cases score 1.0 on Claude Code 2.1.283 with no Bash grant (the
manual review path), about $1.70 per single-run pass. The `evals/` suite has one case per fixture plus a pasted-text case; each case checks that Claude
names the right resource, gives the right verdict, and mentions the right fix, and that the review
skill was what produced the answer. Fixtures are generated by `tests/gen_fixtures.py` and contain
no real identifiers.

## Troubleshooting

- **"has not been reviewed"** on apply — run `/whatbreaks:review <that file>`; if you re-planned,
  the file changed and needs a fresh review.
- **The gate denies but you already reviewed** — the review was probably run on a JSON without
  `--plan-file`, so no marker matches the binary file. Re-run `/whatbreaks:review <plan-file>`.
- **`python3: command not found`** — install Python 3.8+ or use the manual review path (Claude falls
  back to `references/reading-a-plan.md`).
- **The review says the JSON is state, not a plan** — `terraform show -json` with no file argument
  prints state; run `terraform plan -out=tfplan` first and pass `tfplan` to `show -json`.
- **Nothing happens in chat when I type `/whatbreaks:review`** — in chat, skills run when Claude
  decides they fit; just ask for the review in words and attach the plan.

## Security and contact

Report vulnerabilities or false negatives (a dangerous change the rules missed) by opening a
GitHub issue on this repository, or by email to the address in the directory listing. False
negatives get the same priority as bugs. There is no telemetry.

## License

MIT — see [LICENSE](LICENSE).
