---
name: azure-nsg-any
description: "Azure plan for a new NSG rule and a role assignment. Please review before I apply."
tags: ["azure", "exposure", "iam"]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]
---

Azure plan for a new NSG rule and a role assignment. Please review before I apply.

This is the output of `terraform show -json tfplan`:

```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.8",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "azurerm_network_security_rule.rdp",
          "mode": "managed",
          "type": "azurerm_network_security_rule",
          "name": "rdp",
          "provider_name": "registry.terraform.io/hashicorp/azurerm",
          "schema_version": 0,
          "values": {
            "name": "allow-rdp",
            "priority": 100,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Tcp",
            "source_port_range": "*",
            "destination_port_range": "3389",
            "source_address_prefix": "*",
            "destination_address_prefix": "*",
            "resource_group_name": "rg-app",
            "network_security_group_name": "nsg-app"
          },
          "sensitive_values": {}
        },
        {
          "address": "azurerm_role_assignment.ci_owner",
          "mode": "managed",
          "type": "azurerm_role_assignment",
          "name": "ci_owner",
          "provider_name": "registry.terraform.io/hashicorp/azurerm",
          "schema_version": 0,
          "values": {
            "scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
            "role_definition_name": "Owner",
            "principal_id": "00000000-0000-0000-0000-000000000001"
          },
          "sensitive_values": {}
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "azurerm_network_security_rule.rdp",
      "mode": "managed",
      "type": "azurerm_network_security_rule",
      "name": "rdp",
      "provider_name": "registry.terraform.io/hashicorp/azurerm",
      "change": {
        "actions": [
          "create"
        ],
        "before": null,
        "after": {
          "name": "allow-rdp",
          "priority": 100,
          "direction": "Inbound",
          "access": "Allow",
          "protocol": "Tcp",
          "source_port_range": "*",
          "destination_port_range": "3389",
          "source_address_prefix": "*",
          "destination_address_prefix": "*",
          "resource_group_name": "rg-app",
          "network_security_group_name": "nsg-app"
        },
        "after_unknown": {
          "id": true
        },
        "before_sensitive": false,
        "after_sensitive": {}
      }
    },
    {
      "address": "azurerm_role_assignment.ci_owner",
      "mode": "managed",
      "type": "azurerm_role_assignment",
      "name": "ci_owner",
      "provider_name": "registry.terraform.io/hashicorp/azurerm",
      "change": {
        "actions": [
          "create"
        ],
        "before": null,
        "after": {
          "scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
          "role_definition_name": "Owner",
          "principal_id": "00000000-0000-0000-0000-000000000001"
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
