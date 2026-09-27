---
name: s3-public-block-off
description: "Marketing wants the assets bucket public. Here's the plan. Anything I should worry about?"
tags: ["aws", "exposure"]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]
---

Marketing wants the assets bucket public. Here's the plan. Anything I should worry about?

This is the output of `terraform show -json tfplan`:

```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.8",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket_public_access_block.assets",
          "mode": "managed",
          "type": "aws_s3_bucket_public_access_block",
          "name": "assets",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "id": "example-assets",
            "bucket": "example-assets",
            "block_public_acls": false,
            "block_public_policy": false,
            "ignore_public_acls": false,
            "restrict_public_buckets": false
          },
          "sensitive_values": {}
        },
        {
          "address": "aws_s3_bucket_policy.assets",
          "mode": "managed",
          "type": "aws_s3_bucket_policy",
          "name": "assets",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "bucket": "example-assets",
            "policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Sid\": \"PublicRead\", \"Effect\": \"Allow\", \"Principal\": \"*\", \"Action\": \"s3:GetObject\", \"Resource\": \"arn:aws:s3:::example-assets/*\"}]}"
          },
          "sensitive_values": {}
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_s3_bucket_public_access_block.assets",
      "mode": "managed",
      "type": "aws_s3_bucket_public_access_block",
      "name": "assets",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "update"
        ],
        "before": {
          "id": "example-assets",
          "bucket": "example-assets",
          "block_public_acls": true,
          "block_public_policy": true,
          "ignore_public_acls": true,
          "restrict_public_buckets": true
        },
        "after": {
          "id": "example-assets",
          "bucket": "example-assets",
          "block_public_acls": false,
          "block_public_policy": false,
          "ignore_public_acls": false,
          "restrict_public_buckets": false
        },
        "after_unknown": {},
        "before_sensitive": {},
        "after_sensitive": {}
      }
    },
    {
      "address": "aws_s3_bucket_policy.assets",
      "mode": "managed",
      "type": "aws_s3_bucket_policy",
      "name": "assets",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "create"
        ],
        "before": null,
        "after": {
          "bucket": "example-assets",
          "policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Sid\": \"PublicRead\", \"Effect\": \"Allow\", \"Principal\": \"*\", \"Action\": \"s3:GetObject\", \"Resource\": \"arn:aws:s3:::example-assets/*\"}]}"
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
