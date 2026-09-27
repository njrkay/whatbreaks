---
name: pasted-text-plan
description: Reviews a pasted human-readable plan without JSON.
tags: ["smoke", "aws", "text"]
max_turns: 10
timeout_seconds: 300
allowed_tools: [Read, Glob, Grep, Skill]
---

Here's what terraform plan printed. Is it safe to apply?

```
Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  ~ update in-place
-/+ destroy and then create replacement

Terraform will perform the following actions:

  # aws_db_instance.main must be replaced
-/+ resource "aws_db_instance" "main" {
      ~ address                = "db-prod.abc123.us-east-1.rds.amazonaws.com" -> (known after apply)
      ~ arn                    = "arn:aws:rds:us-east-1:111111111111:db:db-prod" -> (known after apply)
        identifier             = "db-prod"
      ~ master_username        = "app" -> "appadmin" # forces replacement
        skip_final_snapshot    = true
        deletion_protection    = false
        backup_retention_period = 7
        # (30 unchanged attributes hidden)
    }

  # aws_lambda_function.api will be updated in-place
  ~ resource "aws_lambda_function" "api" {
        id                     = "api"
      ~ runtime                = "python3.11" -> "python3.12"
        # (20 unchanged attributes hidden)
    }

Plan: 1 to add, 1 to change, 1 to destroy.
```
