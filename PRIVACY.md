# Privacy

WhatBreaks runs on your machine and collects nothing. There is no telemetry, no account, and
no service behind it: the plugin's own code makes no network requests.

## What it reads

- The Terraform / OpenTofu / Terragrunt plan you point it at, either as `terraform show -json`
  output or as a binary plan file that it renders to JSON with the same tool you use.
- In Claude Code and Cowork, the apply gate reads the command Claude is about to run and the
  plan file that command names, to check whether that exact file was reviewed.

## What it writes

- With no plan given, `whatbreaks.tfplan` and `whatbreaks.tfplan.json` in the working
  directory; with a plan file, `<plan>.json` beside it. These hold your plan's values in clear
  text, exactly as Terraform would print them: keep them out of version control and delete
  them when done.
- Review markers under the plugin's data directory (`~/.claude/plugins/data/…/reviews`): the
  plan file's path and hash, the verdict and finding counts, timestamps, and for an approval
  the reason you gave. No plan values are stored there. Delete the directory to forget every
  review.

## What leaves your machine

Nothing, from the plugin. Two things outside it do what they always do:

- When the review skill runs `terraform plan` or `terraform show` for you, Terraform itself
  talks to your state backend and providers with your existing configuration, exactly as it
  would from your shell.
- In chat on claude.ai, a plan you paste or upload is processed by Claude inside your
  conversation, under Anthropic's own privacy policy. `redact_plan.py` is included so you can
  strip sensitive values and account identifiers before sharing a plan anywhere.

## Sensitive values

The analyzer honours the plan's `*_sensitive` maps and never prints a value Terraform marks
sensitive; findings on such attributes are reported without their values.

## Contact

Questions or concerns: https://github.com/njrkay/whatbreaks/issues
