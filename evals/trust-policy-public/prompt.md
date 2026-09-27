---
name: trust-policy-public
description: "Two IAM role trust policy updates. Do these look right to you?"
tags: ["aws", "iam"]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]
---

Two IAM role trust policy updates. Do these look right to you?

This is the output of `terraform show -json tfplan`:

```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.8",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_iam_role.support",
          "mode": "managed",
          "type": "aws_iam_role",
          "name": "support",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "id": "support",
            "name": "support",
            "assume_role_policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Principal\": {\"AWS\": \"*\"}, \"Action\": \"sts:AssumeRole\"}]}"
          },
          "sensitive_values": {}
        },
        {
          "address": "aws_iam_role.github_deploy",
          "mode": "managed",
          "type": "aws_iam_role",
          "name": "github_deploy",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "id": "github-deploy",
            "name": "github-deploy",
            "assume_role_policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Principal\": {\"Federated\": \"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com\"}, \"Action\": \"sts:AssumeRoleWithWebIdentity\", \"Condition\": {\"StringEquals\": {\"token.actions.githubusercontent.com:aud\": \"sts.amazonaws.com\"}}}]}"
          },
          "sensitive_values": {}
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_iam_role.support",
      "mode": "managed",
      "type": "aws_iam_role",
      "name": "support",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "update"
        ],
        "before": {
          "id": "support",
          "name": "support",
          "assume_role_policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Principal\": {\"AWS\": \"arn:aws:iam::111111111111:root\"}, \"Action\": \"sts:AssumeRole\"}]}"
        },
        "after": {
          "id": "support",
          "name": "support",
          "assume_role_policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Principal\": {\"AWS\": \"*\"}, \"Action\": \"sts:AssumeRole\"}]}"
        },
        "after_unknown": {},
        "before_sensitive": {},
        "after_sensitive": {}
      }
    },
    {
      "address": "aws_iam_role.github_deploy",
      "mode": "managed",
      "type": "aws_iam_role",
      "name": "github_deploy",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "update"
        ],
        "before": {
          "id": "github-deploy",
          "name": "github-deploy",
          "assume_role_policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Principal\": {\"Federated\": \"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com\"}, \"Action\": \"sts:AssumeRoleWithWebIdentity\", \"Condition\": {\"StringEquals\": {\"token.actions.githubusercontent.com:aud\": \"sts.amazonaws.com\"}, \"StringLike\": {\"token.actions.githubusercontent.com:sub\": \"repo:example/app:ref:refs/heads/main\"}}}]}"
        },
        "after": {
          "id": "github-deploy",
          "name": "github-deploy",
          "assume_role_policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Principal\": {\"Federated\": \"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com\"}, \"Action\": \"sts:AssumeRoleWithWebIdentity\", \"Condition\": {\"StringEquals\": {\"token.actions.githubusercontent.com:aud\": \"sts.amazonaws.com\"}}}]}"
        },
        "after_unknown": {},
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
