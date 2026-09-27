---
name: rds-replace
description: "I'm about to apply this to production. I only changed the DB admin username. Is it safe?"
tags: ["smoke", "aws", "destructive"]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]
---

I'm about to apply this to production. I only changed the DB admin username. Is it safe?

This is the output of `terraform show -json tfplan`:

```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.8",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_db_instance.main",
          "mode": "managed",
          "type": "aws_db_instance",
          "name": "main",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "identifier": "db-prod",
            "engine": "postgres",
            "engine_version": "16.3",
            "instance_class": "db.r6g.large",
            "allocated_storage": 200,
            "master_username": "appadmin",
            "password": "REDACTED",
            "skip_final_snapshot": true,
            "deletion_protection": false,
            "backup_retention_period": 7,
            "multi_az": true,
            "publicly_accessible": false,
            "storage_encrypted": true,
            "tags": {
              "env": "prod"
            }
          },
          "sensitive_values": {
            "password": true
          }
        },
        {
          "address": "aws_lambda_function.api",
          "mode": "managed",
          "type": "aws_lambda_function",
          "name": "api",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "id": "api",
            "function_name": "api",
            "runtime": "python3.12",
            "memory_size": 256,
            "timeout": 10
          },
          "sensitive_values": {}
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_db_instance.main",
      "mode": "managed",
      "type": "aws_db_instance",
      "name": "main",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "delete",
          "create"
        ],
        "before": {
          "id": "db-prod",
          "identifier": "db-prod",
          "engine": "postgres",
          "engine_version": "16.3",
          "instance_class": "db.r6g.large",
          "allocated_storage": 200,
          "master_username": "app",
          "password": "REDACTED",
          "skip_final_snapshot": true,
          "deletion_protection": false,
          "backup_retention_period": 7,
          "multi_az": true,
          "publicly_accessible": false,
          "storage_encrypted": true,
          "tags": {
            "env": "prod"
          }
        },
        "after": {
          "identifier": "db-prod",
          "engine": "postgres",
          "engine_version": "16.3",
          "instance_class": "db.r6g.large",
          "allocated_storage": 200,
          "master_username": "appadmin",
          "password": "REDACTED",
          "skip_final_snapshot": true,
          "deletion_protection": false,
          "backup_retention_period": 7,
          "multi_az": true,
          "publicly_accessible": false,
          "storage_encrypted": true,
          "tags": {
            "env": "prod"
          }
        },
        "after_unknown": {
          "tags": {},
          "id": true,
          "address": true,
          "endpoint": true
        },
        "before_sensitive": {
          "password": true
        },
        "after_sensitive": {
          "password": true
        },
        "replace_paths": [
          [
            "master_username"
          ]
        ]
      },
      "action_reason": "replace_because_cannot_update"
    },
    {
      "address": "aws_lambda_function.api",
      "mode": "managed",
      "type": "aws_lambda_function",
      "name": "api",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "update"
        ],
        "before": {
          "id": "api",
          "function_name": "api",
          "runtime": "python3.11",
          "memory_size": 256,
          "timeout": 10
        },
        "after": {
          "id": "api",
          "function_name": "api",
          "runtime": "python3.12",
          "memory_size": 256,
          "timeout": 10
        },
        "after_unknown": {
          "last_modified": true
        },
        "before_sensitive": {},
        "after_sensitive": {}
      }
    }
  ],
  "output_changes": {},
  "configuration": {
    "provider_config": {},
    "root_module": {}
  },
  "timestamp": "2026-09-26T10:00:00Z",
  "applyable": true,
  "complete": true,
  "errored": false
}
```
