---
name: iam-admin-wildcard
description: "Review this plan for me. We're updating a deploy policy and attaching a policy to the CI role."
tags: ["aws", "iam"]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]
---

Review this plan for me. We're updating a deploy policy and attaching a policy to the CI role.

This is the output of `terraform show -json tfplan`:

```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.8",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_iam_policy.deploy",
          "mode": "managed",
          "type": "aws_iam_policy",
          "name": "deploy",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "id": "arn:aws:iam::111111111111:policy/deploy",
            "name": "deploy",
            "policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Sid\": \"ReadArtifacts\", \"Effect\": \"Allow\", \"Action\": [\"s3:GetObject\", \"s3:ListBucket\"], \"Resource\": [\"arn:aws:s3:::example-artifacts\", \"arn:aws:s3:::example-artifacts/*\"]}, {\"Sid\": \"Temp\", \"Effect\": \"Allow\", \"Action\": \"*\", \"Resource\": \"*\"}]}"
          },
          "sensitive_values": {}
        },
        {
          "address": "aws_iam_role_policy_attachment.ci_admin",
          "mode": "managed",
          "type": "aws_iam_role_policy_attachment",
          "name": "ci_admin",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "role": "ci-runner",
            "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"
          },
          "sensitive_values": {}
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_iam_policy.deploy",
      "mode": "managed",
      "type": "aws_iam_policy",
      "name": "deploy",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "update"
        ],
        "before": {
          "id": "arn:aws:iam::111111111111:policy/deploy",
          "name": "deploy",
          "policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Sid\": \"ReadArtifacts\", \"Effect\": \"Allow\", \"Action\": [\"s3:GetObject\", \"s3:ListBucket\"], \"Resource\": [\"arn:aws:s3:::example-artifacts\", \"arn:aws:s3:::example-artifacts/*\"]}]}"
        },
        "after": {
          "id": "arn:aws:iam::111111111111:policy/deploy",
          "name": "deploy",
          "policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Sid\": \"ReadArtifacts\", \"Effect\": \"Allow\", \"Action\": [\"s3:GetObject\", \"s3:ListBucket\"], \"Resource\": [\"arn:aws:s3:::example-artifacts\", \"arn:aws:s3:::example-artifacts/*\"]}, {\"Sid\": \"Temp\", \"Effect\": \"Allow\", \"Action\": \"*\", \"Resource\": \"*\"}]}"
        },
        "after_unknown": {},
        "before_sensitive": {},
        "after_sensitive": {}
      }
    },
    {
      "address": "aws_iam_role_policy_attachment.ci_admin",
      "mode": "managed",
      "type": "aws_iam_role_policy_attachment",
      "name": "ci_admin",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "create"
        ],
        "before": null,
        "after": {
          "role": "ci-runner",
          "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"
        },
        "after_unknown": {
          "id": true
        },
        "before_sensitive": false,
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
