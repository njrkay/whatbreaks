---
name: review
description: >-
  Reviews a Terraform or OpenTofu plan for risk before it is applied: what the apply will destroy,
  replace, expose to the internet, or weaken (deletion protection, backups, IAM), ranked by
  severity with a concrete fix for each finding. Use when the user shares a plan (JSON from
  `terraform show -json`, or pasted `terraform plan` text), asks "is this safe to apply", "what will
  this plan do", "what breaks if I apply this", "review my terraform plan", or wants to run
  `terraform apply` / `tofu apply` / `terragrunt apply`. Also use before applying any plan yourself.
argument-hint: "[plan-file | plan.json]"
allowed-tools: >-
  Read Glob Grep
  Bash(python3 ${CLAUDE_SKILL_DIR}/scripts/analyze_plan.py *)
  Bash(python3 ${CLAUDE_SKILL_DIR}/scripts/redact_plan.py *)
  Bash(terraform plan *) Bash(terraform show *) Bash(terraform version *)
  Bash(tofu plan *) Bash(tofu show *) Bash(tofu version *)
  Bash(terragrunt plan *) Bash(terragrunt show *)
---

# Review a Terraform / OpenTofu plan

Produce a verdict-first risk review of a plan, then explain in plain language what would break,
and give the fix for each finding. The review is **read-only**: never run `apply` or `destroy`,
never edit configuration unless the user asks for the fix to be made, and never print a value the
plan marks as sensitive.

## 1. Get the plan as JSON

Work out which of these situations applies and act accordingly. `$ARGUMENTS` may be empty, a
binary plan file, or a JSON file.

| Situation | What to do |
|---|---|
| A binary plan file (e.g. `tfplan`) is given or exists | `terraform show -json <file> > <file>.json` (use `tofu` when the project uses OpenTofu, `terragrunt show -json` for Terragrunt modules) |
| No argument and this is a Terraform working directory (Claude Code / Cowork) | `terraform plan -out=whatbreaks.tfplan` with the var files and workspace the user normally uses (ask if several environments exist and none was named), then `terraform show -json whatbreaks.tfplan > whatbreaks.tfplan.json` |
| A JSON file path is given, or the user attached/uploaded a JSON file | Use it directly. If it has `values` but no `resource_changes`, it is state JSON, not a plan; ask for `terraform show -json <planfile>` output |
| The user pasted plan **text** (`terraform plan` output) | Skip the script; review by hand using `references/reading-a-plan.md`, and say the review was manual |
| The JSON is very large (many MB) | Run `python3 ${CLAUDE_SKILL_DIR}/scripts/redact_plan.py <json> --drop-noop -o <json>.slim.json` first, then analyze the slim file |

Never ask the user to run `apply` to "see what happens". Never run `plan` with `-destroy` unless the
user asked to review a destroy.

## 2. Run the analyzer

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/analyze_plan.py <plan.json> --plan-file <binary-plan-if-any> --marker-dir "${CLAUDE_PLUGIN_DATA}/reviews"
```

- Pass `--plan-file` whenever a binary plan exists: the apply gate recognises the review by the
  hash of that exact file. Without it the gate cannot match a later `terraform apply <file>`.
- In chat on claude.ai there is no plugin data directory and no apply gate; omit `--marker-dir`
  (the script also skips markers on its own if the variable is not substituted).
- Add `--format json` when you need to post-process findings; the default Markdown is for reading.
- If `python3` is unavailable, review by hand with `references/reading-a-plan.md` and
  `references/resource-catalog.md`, and say so.

The script is deterministic and only reads the plan. Its findings carry rule IDs (`WB-D…`
destructive, `WB-S…` safety mechanism removed, `WB-N…` network exposure, `WB-I…` IAM widening,
`WB-P…` plan-level). Its verdict is **BLOCK** (any critical), **WARN** (any high), **REVIEW** (any
medium), or **OK**.

## 3. Write the review

Do not paste the script output as the whole answer. Read it, then write the review for a human
who is about to type `apply`:

1. **Verdict line first**, in bold: the verdict, the plan summary (`N to add, N to change, N to
   destroy, N to replace`), and one sentence on why.
2. **What breaks.** For each CRITICAL and HIGH finding, say what the person would actually
   observe: "the production Postgres instance is destroyed and recreated empty, with no final
   snapshot", "port 22 becomes reachable from the whole internet", "any AWS account could assume
   this role". Name the resource address and the attribute that causes it.
3. **The fix**, as a snippet the person can paste, taken from `references/fix-playbook.md` and
   adapted to their addresses. When a delete looks like a rename (a `delete` with
   `delete_because_no_resource_config` beside a `create` of the same type with matching values),
   propose the exact `moved` block and ask whether that was the intent rather than assuming.
4. **Medium and low findings** in a short list; info findings in one line.
5. **What else changes**: the creates and in-place updates that raised no findings, so the reader
   knows the whole plan was looked at.
6. **Before you apply**: the checks that matter for this plan (backup taken and restore tested,
   dependents notified, maintenance window, correct workspace/backend).
7. **Gate status** (Claude Code / Cowork only): whether `terraform apply <file>` is now allowed.
   For BLOCK say plainly that the apply gate will deny it until the user explicitly accepts the
   risk, and that they can do that with `/whatbreaks:approve <plan-file>`. Do not run the approve
   step yourself.

Keep judgement honest: an OK verdict means the rules found nothing destructive, exposing, or
privilege-widening; it does not certify the change is correct. If something in the plan looks
odd but no rule fired (an unexpected provider, a change in a module nobody touched, a large
number of unknown values), say so.

## 4. Sensitive data

The plan may contain secrets and identifiers. The script masks values marked sensitive; do the
same in anything you write, including "before/after" quotes. If the user wants to share the plan
elsewhere (a ticket, a chat), offer `redact_plan.py --mask-accounts`, which also drops the bulky
`configuration` and `prior_state` sections.

## References

- `references/reading-a-plan.md` — actions, `action_reason` meanings, text-plan symbols, severity table (manual mode)
- `references/resource-catalog.md` — which resource types are rated CRITICAL / HIGH / LOW on destroy or replace, admin ports, escalation actions, broad roles
- `references/fix-playbook.md` — `moved` / `removed` / `lifecycle` snippets, protection flags, network and IAM fixes, the safe apply workflow
