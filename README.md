# WhatBreaks

**Risk review for Terraform and OpenTofu plans, before you apply.**

`whatbreaks` reads the JSON that `terraform show -json <planfile>` produces and tells you what the
apply would actually do to your infrastructure: what gets destroyed or replaced (and whether that
loses data), what becomes reachable from the internet, which safety mechanisms are switched off,
and which IAM changes hand out more power than they should. Every finding is ranked by severity
and comes with a concrete fix. In Claude Code and Cowork, an apply gate refuses to run
`terraform apply` until the exact plan file has been reviewed.

It works for any provider. AWS, Google Cloud, Azure, Kubernetes, and Helm resources are
catalogued; unknown providers are rated by heuristics. OpenTofu and Terragrunt are supported
(see the Terragrunt note under limits).

> Terraform is a trademark of HashiCorp, Inc. OpenTofu and Terragrunt are trademarks of their
> respective owners. This is an independent project, not affiliated with HashiCorp, the OpenTofu
> project, Gruntwork, or Anthropic.

**Try it in ten seconds, no Terraform needed:**

```bash
python3 skills/review/scripts/analyze_plan.py evals/rds-replace/resources/plan.json
```

## What it does

| Component | Where it runs | What it does |
|---|---|---|
| `/whatbreaks:review [plan-file\|plan.json]` (skill) | chat, Cowork, Claude Code | Renders the plan to JSON if needed, runs the deterministic analyzer, then writes a verdict-first review: what breaks, the fix for each finding, what else changes, what to check before applying. Also triggers on its own when you share a plan or ask whether one is safe. |
| `/whatbreaks:approve <plan-file>` (skill) | Cowork, Claude Code | Records your explicit decision to apply a plan whose verdict was **BLOCK**. In Claude Code it is user-invoked only (`disable-model-invocation`): Claude cannot start it, and the skill makes Claude restate the findings and wait for your words before recording anything. Like the gate, it is a workflow guard, not a security boundary: a direct Bash call to the script still appears as an ordinary permission prompt. `--revoke` deletes the marker so the plan must be reviewed again; `--force` (approve a never-reviewed file) exists for emergencies and is never used without you asking for it. |
| Apply gate (hook, `hooks/apply-gate.sh`) | Cowork, Claude Code | A `PreToolUse` hook on the Bash tool. Denies `terraform`/`tofu`/`terragrunt` `apply` and `destroy` unless the plan file named in the command has a review marker (or an approval after BLOCK). Also denies `-auto-approve` without a saved plan, any command that writes files and applies in the same line (`plan -out … && apply`, a copy, a redirection), approvals injected through a pipe or an environment variable, shells and remote shells handed a command string, a binary named through a variable, and `terragrunt run-all apply`. Plain bash that runs nothing but a hash tool on the plan file. |
| `skills/review/scripts/analyze_plan.py` | everywhere Python 3.9+ runs | The rule engine. Standard library only, no network. Usable on its own and in CI (`--exit-code`). |
| `skills/review/scripts/redact_plan.py` | everywhere | Strips sensitive values, URL-embedded credentials, and bulky sections from a plan JSON so it can be shared or uploaded to chat. |

Those four files plus `skills/approve/scripts/approve_plan.py` are the complete list of code that runs.

Verdicts: **BLOCK** (any critical finding), **WARN** (any high), **REVIEW** (any medium), **OK**.
OK means the rules found nothing critical, high, or medium; it does not mean the change is correct.

### What the analyzer looks for

- **Destructive changes** — every delete and replace, rated by what the resource type holds
  (data → CRITICAL, live endpoint/control → HIGH, unknown or a sub-resource → MEDIUM, revisioned
  types such as task definitions → LOW, stateless → LOW), with Terraform's own reason decoded:
  ForceNew attribute, taint, `-replace`, a resource removed from configuration, a `count`/`for_each`
  index shift, a removed module. A delete paired with a matching create of the same type is
  reported as a probable rename with the exact `moved` block. Destroy plans (3+ deletes and
  nothing else) are called out; missing final snapshots, `force_destroy`, KMS deletion windows,
  and containers that delete everything inside them (namespaces, resource groups) are noted.
- **Safety mechanisms weakened** — `deletion_protection`, `skip_final_snapshot`, `force_destroy`,
  backup retention, point-in-time recovery, S3 versioning and public-access-block settings,
  encryption flags, logging/audit controls, KMS deletion window, permissions boundaries, minimum
  TLS, GuardDuty / AWS Config / Macie switched off, secret recovery windows, log retention, major
  database upgrades with `apply_immediately`, services scaled to zero.
- **Network exposure** — security groups, `aws_vpc_security_group_ingress_rule`, GCP firewalls,
  Azure NSGs and NSG rules gaining `0.0.0.0/0`, `::/0`, or `*` sources (admin/database ports and
  all-ports rules CRITICAL, alternate web ports HIGH, 80/443 or ICMP LOW); public database
  toggles, public bucket ACLs, Lambda URLs without auth, Cloud SQL authorized networks, Azure
  database firewall rules, EKS public endpoints, VM external IPs, internet-facing load balancers,
  repositories made public.
- **IAM widening** — new `Action: *` / `Resource: *` statements, `NotAction` / `NotPrincipal`
  allows, service-wide wildcards, `iam:PassRole` on `*`, privilege-escalation actions, trust
  policies assumable by anyone or by other accounts, GitHub OIDC trusts without a `sub` condition,
  public resource policies, admin managed-policy attachments (including via `managed_policy_arns`
  and inline policies), static credentials, GCP `allUsers` / `roles/owner` bindings (including
  members added to an existing binding) and authoritative IAM policies, Azure `Owner` /
  `Contributor` at subscription scope (by name or role-definition id), Kubernetes `cluster-admin`
  bound to broad groups. The account that owns the plan is inferred from its ARNs, so the standard
  "account root" statements (the default KMS key policy, same-account trusts) and `Principal: *`
  scoped by `aws:SourceArn` / `aws:SourceAccount` / `aws:PrincipalOrgID` are reported as INFO/LOW,
  not as alarms. Pre-existing issues are reported separately from ones this plan introduces.
- **Plan-level** — errored plans, partial plans (`-target`, deferred changes), large blast radius,
  drift, imports.

Tier catalogue, ports, roles, and rule-ID families:
[`skills/review/references/resource-catalog.md`](https://github.com/njrkay/whatbreaks/blob/main/skills/review/references/resource-catalog.md).
Reading a plan by hand:
[`reading-a-plan.md`](https://github.com/njrkay/whatbreaks/blob/main/skills/review/references/reading-a-plan.md).
Fixes:
[`fix-playbook.md`](https://github.com/njrkay/whatbreaks/blob/main/skills/review/references/fix-playbook.md).

## Install

From the directory in Claude: **Customize → Plugins**, search for *WhatBreaks*. A plugin added
there follows your account: it is available in chat and Cowork, and appears in Claude Code as a
synced plugin at the next session start.

For development, straight from a checkout:

```bash
claude --plugin-dir ./whatbreaks
```

Requirements: Python 3.9+ on the machine where the review runs (Claude's chat sandbox has it), and
`terraform`/`tofu` on `PATH` if you want Claude to produce the plan for you. The apply gate needs
Claude Code or Cowork and a `bash` on the machine; it has no effect in chat.

## Use it

**In chat (claude.ai):** attach the output of `terraform show -json tfplan` and ask. That JSON
holds every value in clear text, including the ones Terraform marks sensitive (passwords, keys,
connection strings), so run `python3 skills/review/scripts/redact_plan.py plan.json --mask-accounts`
on it first if it contains anything you would not paste into a ticket. Pasting the `terraform plan`
text works too (a manual, less exhaustive review).

**In Claude Code / Cowork:**

```
/whatbreaks:review               # runs a fresh plan in the current root module and reviews it
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
python3 skills/review/scripts/analyze_plan.py plan.json --exit-code     # exit 2 on BLOCK, 1 on WARN, 3 on unreadable input
python3 skills/review/scripts/analyze_plan.py plan.json --format json  # machine-readable findings
```

## How the apply gate works, and its limits

The gate is a speed bump that makes the safe workflow the only convenient one, not a security
boundary.

- It keys reviews on the SHA-256 of the plan file. Re-running `terraform plan` produces a new file
  that needs its own review; editing the file invalidates the review. It cannot verify that the
  JSON you reviewed was rendered from that file, so pair a JSON only with its own plan.
- Markers live in `${CLAUDE_PLUGIN_DATA}/reviews` (Claude Code's per-plugin data directory under
  `~/.claude/plugins/data/`). Each marker holds the plan file's absolute path and hash, the JSON's
  hash, the verdict and finding counts, timestamps, and for approvals the reason you gave; no plan
  values. Delete the directory to forget all reviews. Claude can write a marker file directly; the
  hook does not verify who produced it.
- A denial applies in every permission mode, including bypass mode: hook decisions are separate
  from the permission system (per the Claude Code hooks reference; verified on 2.1.283).
- It only sees the command string. It looks through `cd`, `sudo`, `timeout` and other
  wrappers, shells and remote shells given a command string (also any wrapper whose `-c`, `--run`
  or `--command` flag carries one), `&&`/`;`/`|` chains, subshells, loops and `-chdir`, and it treats `TF_CLI_ARGS`, `yes |`, and stdin redirection as auto-approve. A
  binary named through a variable (`$TF apply`) is denied when the same command mentions terraform
  and invisible when the variable was set earlier. It cannot see inside a script file, a Makefile
  target, or an alias (`./deploy.sh`, `make apply`), and it does not gate `state push`/`state rm`,
  `import`, or `taint`. If your team applies through a wrapper, add a `PreToolUse` rule for it or
  rely on the review skill. A command too long or too fragmented to parse within the hook timeout
  (over 128 KiB, 50,000 quotes and escapes, 2,000 lines, 300 parts, or 4,000 words and quotes
  outside here-documents) is
  denied rather than risked, since a timed-out hook does not block.
- Terragrunt runs Terraform inside `.terragrunt-cache/…`, so give `-out` an absolute path; a
  relative plan file cannot be found by `--plan-file` or by the gate.
- HCP Terraform / Terraform Enterprise remote runs do not produce a local plan file, so every
  apply is denied; turn the gate off and review the run's JSON plan from the workspace instead.
- Windows: the hook needs a `bash` (Git Bash); without one it cannot start, and Claude Code treats
  a hook that fails to start as non-blocking, so the apply proceeds ungated. Commands run through
  the PowerShell tool are not gated. Tested on Linux and macOS.
- Turn it off with the plugin's **apply_gate** option (`/plugin configure whatbreaks@…` in Claude
  Code). Cowork cannot change plugin options, so there the gate stays on; disable the plugin to
  remove it.

## What the plugin reads, runs, writes, and sends

- **Reads:** the plan JSON you point it at (or that it renders with `terraform show -json`), the
  plan file named in an `apply` command (to hash it), and its own marker files. In chat, the skill
  folder including `analyze_plan.py` is copied into Claude's code-execution sandbox and runs there.
- **Runs:** `terraform`/`tofu`/`terragrunt` `plan` (when you ask for a review without a plan file)
  and `show -json` (whenever a binary plan is reviewed), the bundled Python scripts, and the bash
  hook, which runs nothing but `sha256sum` (or `shasum` / `openssl`) on the plan file. Nothing is
  installed; there are no package launchers, no dependencies, no compiled code.
  `.github/` and `tests/` are development files that the plugin never runs.
- **Writes:** with no argument, `whatbreaks.tfplan` and `whatbreaks.tfplan.json` in the working
  directory; with a plan file, `<plan>.json` beside it; for very large JSON, `<plan>.slim.json`.
  These hold your plan's values in clear text: gitignore and delete them. Review markers go under
  `${CLAUDE_PLUGIN_DATA}/reviews`.
- **Sends:** nothing from the plugin's own code; the scripts and the hook make no network calls.
  When the skill runs `terraform plan`/`show` for you, Terraform itself talks to your backend and
  providers with your normal credentials, exactly as it would from your shell.
- **Sensitive values:** never printed. The analyzer honours the plan's `*_sensitive` maps (a finding
  on a sensitive attribute is reported without its values); `redact_plan.py` also masks values under
  secret-looking attribute names, credentials embedded in URLs, and optionally account IDs.

## Test it

```bash
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_fixtures.py   # 26 fixture plans with expected verdicts and findings
bash tests/test_hook.sh                                    # 184 apply-gate scenarios, including known bypass shapes
python3 tests/check_submission.py                          # the directory's pre-submission rules
claude plugin validate .                                   # manifest and component checks
```

The behavioural evals live in `evals/` and run through Claude Code's plugin evaluation command on
your own account; `evals/README.md` gives the command and the tool grants it needs. The suite has
one case per fixture plus a pasted-text case; each checks that Claude names
the right resource, gives the right verdict, mentions the right fix, and that the review skill was
what produced the answer, plus an LLM rubric on the explanation. Fixtures are generated by
`tests/gen_fixtures.py` with Terraform's real `after_unknown` shapes and contain no real
identifiers. Last verified: the nine smoke-tagged cases score 1.0 (9/9) on Claude Code 2.1.283 with no Bash
grant (the manual review path; the container used has no sandbox backend for Bash). CI runs the
analyzer tests on Python 3.9 and 3.12 and the hook tests on Ubuntu and macOS (bash 3.2, BSD sed).

## Troubleshooting

- **"has not been reviewed"** on apply — run `/whatbreaks:review <that file>`; if you re-planned,
  the file changed and needs a fresh review.
- **"writes files and then applies in the same line"** — the gate refuses `plan && apply` (and
  `cp`, `>`, or a fetched file before an apply) because the hash it checks might not be the file Terraform
  reads. Plan, review, then apply as separate commands.
- **The gate denies but you already reviewed** — the review was probably run on a JSON without
  `--plan-file`, so no marker matches the binary file. Re-run `/whatbreaks:review <plan-file>`.
- **`python3: command not found`** — install Python 3.9+ or use the manual review path (Claude falls
  back to `references/reading-a-plan.md`).
- **The review says the JSON is state, not a plan** — `terraform show -json` with no file argument
  prints state; run `terraform plan -out=tfplan` first and pass `tfplan` to `show -json`.
- **Nothing happens in chat when I type `/whatbreaks:review`** — in chat, skills run when Claude
  decides they fit; just ask for the review in words and attach the plan.

## Security and contact

Report vulnerabilities, gate bypasses, or false negatives (a dangerous change the rules missed) at
https://github.com/njrkay/whatbreaks/issues, or by email to the contact address in the directory
listing. False negatives get the same priority as bugs. There is no telemetry.

## License

MIT — see [LICENSE](https://github.com/njrkay/whatbreaks/blob/main/LICENSE).
