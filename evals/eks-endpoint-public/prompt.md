---
name: eks-endpoint-public
description: "We need to reach the EKS API from CI. Here's the change \u2014 safe?"
tags: ["aws", "exposure"]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]
---

We need to reach the EKS API from CI. Here's the change — safe?

This is the output of `terraform show -json tfplan`:

```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.8",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_eks_cluster.prod",
          "mode": "managed",
          "type": "aws_eks_cluster",
          "name": "prod",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "id": "prod",
            "name": "prod",
            "version": "1.31",
            "role_arn": "arn:aws:iam::111111111111:role/eks",
            "vpc_config": [
              {
                "subnet_ids": [
                  "subnet-a",
                  "subnet-b"
                ],
                "endpoint_private_access": true,
                "endpoint_public_access": true,
                "public_access_cidrs": [
                  "0.0.0.0/0"
                ],
                "cluster_security_group_id": "sg-0eks",
                "vpc_id": "vpc-0abc"
              }
            ]
          },
          "sensitive_values": {}
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_eks_cluster.prod",
      "mode": "managed",
      "type": "aws_eks_cluster",
      "name": "prod",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "update"
        ],
        "before": {
          "id": "prod",
          "name": "prod",
          "version": "1.31",
          "role_arn": "arn:aws:iam::111111111111:role/eks",
          "vpc_config": [
            {
              "subnet_ids": [
                "subnet-a",
                "subnet-b"
              ],
              "endpoint_private_access": true,
              "endpoint_public_access": false,
              "public_access_cidrs": [],
              "cluster_security_group_id": "sg-0eks",
              "vpc_id": "vpc-0abc"
            }
          ]
        },
        "after": {
          "id": "prod",
          "name": "prod",
          "version": "1.31",
          "role_arn": "arn:aws:iam::111111111111:role/eks",
          "vpc_config": [
            {
              "subnet_ids": [
                "subnet-a",
                "subnet-b"
              ],
              "endpoint_private_access": true,
              "endpoint_public_access": true,
              "public_access_cidrs": [
                "0.0.0.0/0"
              ],
              "cluster_security_group_id": "sg-0eks",
              "vpc_id": "vpc-0abc"
            }
          ]
        },
        "after_unknown": {
          "vpc_config": [
            {
              "subnet_ids": [
                false,
                false
              ],
              "public_access_cidrs": [
                false
              ]
            }
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
