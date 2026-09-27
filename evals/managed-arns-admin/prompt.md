---
name: managed-arns-admin
description: "Adding a managed policy to the CI role. Anything wrong here?"
tags: ["aws", "iam"]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]
---

Adding a managed policy to the CI role. Anything wrong here?

This is the output of `terraform show -json tfplan`:

```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.8",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_iam_role.ci",
          "mode": "managed",
          "type": "aws_iam_role",
          "name": "ci",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "id": "ci",
            "name": "ci",
            "arn": "arn:aws:iam::111111111111:role/ci",
            "assume_role_policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Principal\": {\"AWS\": \"arn:aws:iam::111111111111:root\"}, \"Action\": \"sts:AssumeRole\"}]}",
            "managed_policy_arns": [
              "arn:aws:iam::aws:policy/ReadOnlyAccess",
              "arn:aws:iam::aws:policy/AdministratorAccess"
            ]
          },
          "sensitive_values": {}
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_iam_role.ci",
      "mode": "managed",
      "type": "aws_iam_role",
      "name": "ci",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "update"
        ],
        "before": {
          "id": "ci",
          "name": "ci",
          "arn": "arn:aws:iam::111111111111:role/ci",
          "assume_role_policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Principal\": {\"AWS\": \"arn:aws:iam::111111111111:root\"}, \"Action\": \"sts:AssumeRole\"}]}",
          "managed_policy_arns": [
            "arn:aws:iam::aws:policy/ReadOnlyAccess"
          ]
        },
        "after": {
          "id": "ci",
          "name": "ci",
          "arn": "arn:aws:iam::111111111111:role/ci",
          "assume_role_policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Principal\": {\"AWS\": \"arn:aws:iam::111111111111:root\"}, \"Action\": \"sts:AssumeRole\"}]}",
          "managed_policy_arns": [
            "arn:aws:iam::aws:policy/ReadOnlyAccess",
            "arn:aws:iam::aws:policy/AdministratorAccess"
          ]
        },
        "after_unknown": {
          "managed_policy_arns": [
            false,
            false
          ]
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
