---
name: deletion-protection-off
description: "Small change to our Aurora cluster before the migration window. Fine to apply?"
tags: ["aws", "safety"]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]
---

Small change to our Aurora cluster before the migration window. Fine to apply?

This is the output of `terraform show -json tfplan`:

```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.8",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_rds_cluster.main",
          "mode": "managed",
          "type": "aws_rds_cluster",
          "name": "main",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "id": "aurora-prod",
            "cluster_identifier": "aurora-prod",
            "engine": "aurora-postgresql",
            "deletion_protection": false,
            "backup_retention_period": 1,
            "skip_final_snapshot": false,
            "final_snapshot_identifier": "aurora-prod-final",
            "master_password": "REDACTED"
          },
          "sensitive_values": {
            "master_password": true
          }
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_rds_cluster.main",
      "mode": "managed",
      "type": "aws_rds_cluster",
      "name": "main",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "update"
        ],
        "before": {
          "id": "aurora-prod",
          "cluster_identifier": "aurora-prod",
          "engine": "aurora-postgresql",
          "deletion_protection": true,
          "backup_retention_period": 14,
          "skip_final_snapshot": false,
          "final_snapshot_identifier": "aurora-prod-final",
          "master_password": "REDACTED"
        },
        "after": {
          "id": "aurora-prod",
          "cluster_identifier": "aurora-prod",
          "engine": "aurora-postgresql",
          "deletion_protection": false,
          "backup_retention_period": 1,
          "skip_final_snapshot": false,
          "final_snapshot_identifier": "aurora-prod-final",
          "master_password": "REDACTED"
        },
        "after_unknown": {},
        "before_sensitive": {
          "master_password": true
        },
        "after_sensitive": {
          "master_password": true
        }
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
