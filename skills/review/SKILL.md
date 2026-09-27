---
name: review
description: >-
  Risk review of a Terraform, OpenTofu, or Terragrunt plan before apply: what the apply will
  destroy, replace, expose to the internet, or weaken (deletion protection, backups, IAM), ranked by
  severity with a fix for each finding, using a bundled deterministic analyzer. Use when the user
  shares a plan as `terraform show -json` JSON (pasted or uploaded; it has `resource_changes`) or
  pasted `terraform plan` text (`Plan: N to add, N to change, N to destroy`, `must be replaced`,
  `forces replacement`), asks whether a plan is safe to apply, what it will do or what breaks, why
  a resource is being replaced or destroyed, or asks you to run `terraform apply` / `tofu apply` /
  `terragrunt apply` (review first). Not for writing or refactoring HCL, provider documentation
  questions, or init/validate/state-lock errors with no plan involved.
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

`$ARGUMENTS` may be empty, a binary plan file, or a JSON file. Work out which situation applies:

| Situation | What to do |
|---|---|
| The user names a binary plan file (e.g. `tfplan`) | `terraform show -json <file> > <file>.json` with the same binary and version that produced it (`show` refuses a plan from another version). Do not reuse an old plan file lying around when the user did not name it. |
| No argument, in a Terraform working directory (Claude Code / Cowork) | Always run a fresh plan. Find the root module first: the directory holding the `*.tf` files (or `terragrunt.hcl`) being changed; if several candidates exist (`envs/*`, `stacks/*`) ask which. Then `terraform plan -out=whatbreaks.tfplan` with the var files and workspace the user normally uses, then `terraform show -json whatbreaks.tfplan > whatbreaks.tfplan.json`. With Terragrunt give `-out` an absolute path (the module directory's full path, e.g. `-out=/srv/repo/infra/whatbreaks.tfplan`): a relative path lands in `.terragrunt-cache/…` where neither `--plan-file` nor the apply gate can find it. If `plan` fails because the directory is not initialised, ask before running `init` (it touches the backend and downloads providers). |
| A JSON file path is given, or the user attached a JSON file | Use it directly. If it has `values` but no `resource_changes`, it is state JSON, not a plan; ask for `terraform show -json <planfile>` output. |
| The user pasted the plan JSON into the message | Save it verbatim to a file first (a temporary directory, not the repository: it may contain secrets), then treat it as a JSON file. |
| In chat, the user uploaded a **binary** plan file | It cannot be rendered there (no terraform binary). Ask for `terraform show -json <file> > plan.json`, passed through `scripts/redact_plan.py --mask-accounts` if it holds anything sensitive. |
| The user pasted plan **text** (`terraform plan` output) | Skip the script; review by hand with `references/reading-a-plan.md`, say the review was manual and less exhaustive, and note that no review marker is written, so the apply gate cannot recognise the file. |
| The JSON is very large (many MB) | `python3 <scripts>/redact_plan.py <json> --drop-noop -o <json>.slim.json` first, then analyze the slim file. |

Which binary: `terragrunt` when `terragrunt.hcl` is present; `tofu` when `.opentofu-version` exists,
`.terraform.lock.hcl` references `registry.opentofu.org`, or only `tofu` is on PATH; otherwise
`terraform`. Never ask the user to run `apply` to "see what happens". Never run `plan -destroy`
unless the user asked to review a destroy.

## 2. Run the analyzer

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/analyze_plan.py <plan.json> --plan-file <binary-plan-if-any> --marker-dir "${CLAUDE_PLUGIN_DATA}/reviews"
```

- Pass `--plan-file` whenever a binary plan exists: the apply gate recognises the review by the
  hash of that exact file, and the gate cannot check that the JSON came from that file, so only
  pair a JSON with the plan it was rendered from.
- In chat on claude.ai `${CLAUDE_SKILL_DIR}` and `${CLAUDE_PLUGIN_DATA}` are not substituted and
  there is no apply gate. The skill folder is copied into the sandbox, so run the script by its
  path relative to this file (`scripts/analyze_plan.py`; locate it with
  `find / -name analyze_plan.py 2>/dev/null` if needed) and omit `--marker-dir` and `--plan-file`.
- Add `--format json` when you need to post-process findings; the default Markdown is for reading.
- If `python3` is unavailable, review by hand with `references/reading-a-plan.md` and
  `references/resource-catalog.md`, and say so.

The script is deterministic and only reads the plan. Findings carry rule IDs: `WB-D…` destructive,
`WB-S…` safety mechanism weakened, `WB-N…` network exposure, `WB-I…` IAM widening (`WB-I000` =
pre-existing, not introduced by this plan), `WB-P…` plan-level, `WB-X…` = the analyzer failed on a
resource, review it by hand. Its verdict is **BLOCK** (any critical), **WARN** (any high),
**REVIEW** (any medium), or **OK**.

## 3. Write the review

Do not paste the script output as the whole answer. Read it, then write the review for a human
who is about to type `apply`:

1. **Verdict line first**, exactly in this shape:
   `**Verdict: BLOCK** — 2 to add, 1 to change, 1 to destroy, 1 to replace — <one sentence why>.`
   Use the verdict word the script printed (BLOCK / WARN / REVIEW / OK); in manual mode derive it
   from `references/reading-a-plan.md` §3.
2. **What breaks.** For each CRITICAL and HIGH finding, say what the person would actually
   observe: "the production Postgres instance is destroyed and recreated empty, with no final
   snapshot", "port 22 becomes reachable from the whole internet", "any AWS account could assume
   this role". Name the resource address and the attribute that causes it.
3. **The fix**, as a snippet the person can paste, adapted to their addresses. The script's Fix
   line usually suffices; open `references/fix-playbook.md` when a full `moved` / `removed` /
   `lifecycle` / IAM snippet is needed. When the script says a delete "looks like a rename",
   give the exact `moved` block and ask whether that was the intent rather than assuming.
4. **Medium and low findings** in a short list; info findings in one line.
5. **What else changes**: the creates and in-place updates that raised no findings, grouped by
   action, at most ~15 addresses then a count, so the reader knows the whole plan was looked at.
6. **Before you apply**: the checks that matter for this plan (backup taken and restore tested,
   dependents notified, maintenance window, correct workspace/backend).
7. **Gate status** (Claude Code / Cowork only): whether `terraform apply <file>` is now allowed.
   For BLOCK say plainly that the apply gate will deny it, and that if the user still wants to
   proceed after reading the findings they must run `/whatbreaks:approve <plan-file>` themselves.
   Never run the approve step, and never write a marker file directly.

For OK with few changes keep the whole review under ~15 lines. Keep judgement honest: OK means
the rules found nothing critical, high, or medium; it does not certify the change is correct. If
something looks odd but no rule fired (an unexpected provider, a change in a module nobody
touched, many unknown values), say so.

## 4. Sensitive data

The plan may contain secrets and identifiers. The script masks values marked sensitive; do the
same in anything you write, including "before/after" quotes. The rendered `*.json` files hold
every value in clear text, including ones Terraform marks sensitive: tell the user to gitignore
and delete them. If the user wants to share the plan elsewhere (a ticket, a chat), offer
`redact_plan.py --mask-accounts`, which also drops the bulky `configuration`, `planned_values`
and `prior_state` sections.

## References

- `references/reading-a-plan.md` — actions, `action_reason` meanings, text-plan phrases, severity table (manual mode)
- `references/resource-catalog.md` — which resource types are rated CRITICAL / HIGH / LOW on destroy or replace, ports, escalation actions, broad roles, rule-ID families
- `references/fix-playbook.md` — `moved` / `removed` / `lifecycle` snippets, protection flags, network and IAM fixes, the safe apply workflow
