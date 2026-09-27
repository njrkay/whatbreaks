---
name: sg-open-ssh
description: "Quick sanity check on this plan before I apply \u2014 it's just an instance resize and a security group tweak."
tags: ["smoke", "aws", "exposure"]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]
---

Quick sanity check on this plan before I apply — it's just an instance resize and a security group tweak.

This is the output of `terraform show -json tfplan`:

```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.8",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_security_group.web",
          "mode": "managed",
          "type": "aws_security_group",
          "name": "web",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "id": "sg-0abc",
            "name": "web",
            "vpc_id": "vpc-0abc",
            "ingress": [
              {
                "cidr_blocks": [
                  "0.0.0.0/0"
                ],
                "description": "https",
                "from_port": 443,
                "to_port": 443,
                "protocol": "tcp",
                "ipv6_cidr_blocks": [],
                "prefix_list_ids": [],
                "security_groups": [],
                "self": false
              },
              {
                "cidr_blocks": [
                  "0.0.0.0/0"
                ],
                "description": "ssh for debugging",
                "from_port": 22,
                "to_port": 22,
                "protocol": "tcp",
                "ipv6_cidr_blocks": [],
                "prefix_list_ids": [],
                "security_groups": [],
                "self": false
              }
            ],
            "egress": [
              {
                "cidr_blocks": [
                  "0.0.0.0/0"
                ],
                "description": "",
                "from_port": 0,
                "to_port": 0,
                "protocol": "-1",
                "ipv6_cidr_blocks": [],
                "prefix_list_ids": [],
                "security_groups": [],
                "self": false
              }
            ],
            "tags": {}
          },
          "sensitive_values": {}
        },
        {
          "address": "aws_instance.web",
          "mode": "managed",
          "type": "aws_instance",
          "name": "web",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "id": "i-0abc",
            "instance_type": "t3.medium",
            "ami": "ami-0abc",
            "tags": {
              "Name": "web"
            }
          },
          "sensitive_values": {}
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_security_group.web",
      "mode": "managed",
      "type": "aws_security_group",
      "name": "web",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "update"
        ],
        "before": {
          "id": "sg-0abc",
          "name": "web",
          "vpc_id": "vpc-0abc",
          "ingress": [
            {
              "cidr_blocks": [
                "0.0.0.0/0"
              ],
              "description": "https",
              "from_port": 443,
              "to_port": 443,
              "protocol": "tcp",
              "ipv6_cidr_blocks": [],
              "prefix_list_ids": [],
              "security_groups": [],
              "self": false
            }
          ],
          "egress": [
            {
              "cidr_blocks": [
                "0.0.0.0/0"
              ],
              "description": "",
              "from_port": 0,
              "to_port": 0,
              "protocol": "-1",
              "ipv6_cidr_blocks": [],
              "prefix_list_ids": [],
              "security_groups": [],
              "self": false
            }
          ],
          "tags": {}
        },
        "after": {
          "id": "sg-0abc",
          "name": "web",
          "vpc_id": "vpc-0abc",
          "ingress": [
            {
              "cidr_blocks": [
                "0.0.0.0/0"
              ],
              "description": "https",
              "from_port": 443,
              "to_port": 443,
              "protocol": "tcp",
              "ipv6_cidr_blocks": [],
              "prefix_list_ids": [],
              "security_groups": [],
              "self": false
            },
            {
              "cidr_blocks": [
                "0.0.0.0/0"
              ],
              "description": "ssh for debugging",
              "from_port": 22,
              "to_port": 22,
              "protocol": "tcp",
              "ipv6_cidr_blocks": [],
              "prefix_list_ids": [],
              "security_groups": [],
              "self": false
            }
          ],
          "egress": [
            {
              "cidr_blocks": [
                "0.0.0.0/0"
              ],
              "description": "",
              "from_port": 0,
              "to_port": 0,
              "protocol": "-1",
              "ipv6_cidr_blocks": [],
              "prefix_list_ids": [],
              "security_groups": [],
              "self": false
            }
          ],
          "tags": {}
        },
        "after_unknown": {},
        "before_sensitive": {},
        "after_sensitive": {}
      }
    },
    {
      "address": "aws_instance.web",
      "mode": "managed",
      "type": "aws_instance",
      "name": "web",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "update"
        ],
        "before": {
          "id": "i-0abc",
          "instance_type": "t3.small",
          "ami": "ami-0abc",
          "tags": {
            "Name": "web"
          }
        },
        "after": {
          "id": "i-0abc",
          "instance_type": "t3.medium",
          "ami": "ami-0abc",
          "tags": {
            "Name": "web"
          }
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
