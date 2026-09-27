---
name: approve
description: >-
  Records the user's explicit decision to apply a plan whose review verdict was BLOCK, so the
  whatbreaks apply gate lets `terraform apply <plan-file>` through; `--revoke` removes it. Runs
  only when the user types /whatbreaks:approve. Never invoke this on your own initiative, to get
  past the apply gate, or because a plan looks fine.
argument-hint: "<plan-file> [--revoke]"
disable-model-invocation: true
allowed-tools: >-
  Read
  Bash(python3 ${CLAUDE_SKILL_DIR}/scripts/approve_plan.py *)
---

# Approve a blocked plan for apply

The apply gate denies `terraform apply <file>` when the review of that file ended in **BLOCK**.
This skill records that the person accepts the risk. It exists so that the decision is theirs and
explicit, not the model's.

If `$ARGUMENTS` contains `--revoke`, skip to **Revoke**.

## Before recording an approval

1. Identify the plan file (`$ARGUMENTS`, or the file from the most recent review in this session).
2. Restate the critical findings from that review in one or two lines each: what is destroyed,
   replaced, exposed, or widened. If the review is not in this conversation, run
   `/whatbreaks:review <plan-file>` first and stop there.
3. Confirm the person has explicitly accepted these consequences **in this conversation** ("yes,
   destroy it, we have a snapshot", "go ahead, the bucket is meant to be public"). A general
   "apply it" given before the findings were shown does not count; ask once, plainly, and wait.
4. Never approve on your own initiative, never as a workaround for the gate, and never because the
   plan "looks fine" — a BLOCK verdict is the whole reason this step exists.

## Record it

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/approve_plan.py <plan-file> --marker-dir "${CLAUDE_PLUGIN_DATA}/reviews" --reason "<the user's words, briefly>"
```

- The script refuses a plan that has no review marker. Do not add `--force` unless the user
  explicitly says to approve an unreviewed plan and understands nothing was checked.
- The approval is tied to the SHA-256 of that exact file. A new `terraform plan` produces a new
  file that needs its own review, and re-running `/whatbreaks:review` on this file resets the
  approval.
- After recording, tell the person that `terraform apply <plan-file>` is now allowed for that
  file. Do not run the apply unless they ask for it.

## Revoke

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/approve_plan.py <plan-file> --marker-dir "${CLAUDE_PLUGIN_DATA}/reviews" --revoke
```

Removes the marker (review and approval), so the next apply is denied until the plan is reviewed
again. Use it when the person changes their mind or the situation changed. `--list` shows the
markers that exist.

## Where this works

Claude Code and Cowork, where the apply gate hook runs and `${CLAUDE_PLUGIN_DATA}` exists. In chat
on claude.ai there is no gate and nothing to approve; say so.
