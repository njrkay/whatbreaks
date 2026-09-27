# Changelog

## 0.1.0 — 2026-09-27

First release.

- `review` skill: verdict-first risk review of Terraform / OpenTofu / Terragrunt plans from
  `terraform show -json` output (chat, Cowork, Claude Code), with a manual path for pasted plan text.
- `approve` skill: user-only acceptance of a BLOCK verdict; `--revoke`.
- Apply gate hook: denies `apply`/`destroy` until the exact plan file has been reviewed; understands
  wrappers, shells, `-chdir`, chains, and fails closed.
- Deterministic analyzer (stdlib only) with destructive, safety, exposure, IAM, and plan-level rule
  families; rename detection; sensitive-value masking; local-account inference.
- `redact_plan.py` for sharing plans safely.
- 26 fixture plans with unit tests, 85 hook scenarios, 27 eval cases.
