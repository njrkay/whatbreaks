---
name: sns-sqs-scoped
description: "Wiring an SNS topic to an SQS queue. The policy has Principal * which makes me nervous \u2014 is it fine?"
tags: ["aws", "iam"]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]
---

Wiring an SNS topic to an SQS queue. The policy has Principal * which makes me nervous — is it fine?

This is the output of `terraform show -json tfplan`:

```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.8",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_sqs_queue_policy.orders",
          "mode": "managed",
          "type": "aws_sqs_queue_policy",
          "name": "orders",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "queue_url": "https://sqs.us-east-1.amazonaws.com/111111111111/orders",
            "policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Sid\": \"AllowSNS\", \"Effect\": \"Allow\", \"Principal\": \"*\", \"Action\": \"sqs:SendMessage\", \"Resource\": \"arn:aws:sqs:us-east-1:111111111111:orders\", \"Condition\": {\"ArnEquals\": {\"aws:SourceArn\": \"arn:aws:sns:us-east-1:111111111111:order-events\"}}}]}"
          },
          "sensitive_values": {}
        },
        {
          "address": "aws_sns_topic_subscription.orders",
          "mode": "managed",
          "type": "aws_sns_topic_subscription",
          "name": "orders",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "topic_arn": "arn:aws:sns:us-east-1:111111111111:order-events",
            "protocol": "sqs",
            "endpoint": "arn:aws:sqs:us-east-1:111111111111:orders"
          },
          "sensitive_values": {}
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_sqs_queue_policy.orders",
      "mode": "managed",
      "type": "aws_sqs_queue_policy",
      "name": "orders",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "create"
        ],
        "before": null,
        "after": {
          "queue_url": "https://sqs.us-east-1.amazonaws.com/111111111111/orders",
          "policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Sid\": \"AllowSNS\", \"Effect\": \"Allow\", \"Principal\": \"*\", \"Action\": \"sqs:SendMessage\", \"Resource\": \"arn:aws:sqs:us-east-1:111111111111:orders\", \"Condition\": {\"ArnEquals\": {\"aws:SourceArn\": \"arn:aws:sns:us-east-1:111111111111:order-events\"}}}]}"
        },
        "after_unknown": {
          "id": true
        },
        "before_sensitive": false,
        "after_sensitive": {}
      }
    },
    {
      "address": "aws_sns_topic_subscription.orders",
      "mode": "managed",
      "type": "aws_sns_topic_subscription",
      "name": "orders",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "create"
        ],
        "before": null,
        "after": {
          "topic_arn": "arn:aws:sns:us-east-1:111111111111:order-events",
          "protocol": "sqs",
          "endpoint": "arn:aws:sqs:us-east-1:111111111111:orders"
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
