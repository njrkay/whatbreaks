---
name: heuristics
description: "Mixed plan across a couple of providers. What's the risk here?"
tags: ["multi-provider", "destructive"]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]
---

Mixed plan across a couple of providers. What's the risk here?

This is the output of `terraform show -json tfplan`:

```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.8",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "foo_database_cluster.main",
          "mode": "managed",
          "type": "foo_database_cluster",
          "name": "main",
          "provider_name": "registry.terraform.io/example/foo",
          "schema_version": 0,
          "values": {
            "name": "main",
            "size": "large"
          },
          "sensitive_values": {}
        },
        {
          "address": "null_resource.provisioner",
          "mode": "managed",
          "type": "null_resource",
          "name": "provisioner",
          "provider_name": "registry.terraform.io/hashicorp/null",
          "schema_version": 0,
          "values": {
            "triggers": {
              "v": "2"
            }
          },
          "sensitive_values": {}
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "cloudflare_zone.example",
      "mode": "managed",
      "type": "cloudflare_zone",
      "name": "example",
      "provider_name": "registry.terraform.io/cloudflare/cloudflare",
      "change": {
        "actions": [
          "delete"
        ],
        "before": {
          "id": "z1",
          "zone": "example.com"
        },
        "after": null,
        "after_unknown": {},
        "before_sensitive": {},
        "after_sensitive": false
      }
    },
    {
      "address": "foo_database_cluster.main",
      "mode": "managed",
      "type": "foo_database_cluster",
      "name": "main",
      "provider_name": "registry.terraform.io/example/foo",
      "change": {
        "actions": [
          "delete",
          "create"
        ],
        "before": {
          "id": "c1",
          "name": "main",
          "size": "small"
        },
        "after": {
          "name": "main",
          "size": "large"
        },
        "after_unknown": {
          "id": true
        },
        "before_sensitive": {},
        "after_sensitive": {},
        "replace_paths": [
          [
            "size"
          ]
        ]
      },
      "action_reason": "replace_because_cannot_update"
    },
    {
      "address": "foo_widget.thing",
      "mode": "managed",
      "type": "foo_widget",
      "name": "thing",
      "provider_name": "registry.terraform.io/example/foo",
      "change": {
        "actions": [
          "delete"
        ],
        "before": {
          "id": "w1"
        },
        "after": null,
        "after_unknown": {},
        "before_sensitive": {},
        "after_sensitive": false
      }
    },
    {
      "address": "null_resource.provisioner",
      "mode": "managed",
      "type": "null_resource",
      "name": "provisioner",
      "provider_name": "registry.terraform.io/hashicorp/null",
      "change": {
        "actions": [
          "delete",
          "create"
        ],
        "before": {
          "id": "1",
          "triggers": {
            "v": "1"
          }
        },
        "after": {
          "triggers": {
            "v": "2"
          }
        },
        "after_unknown": {
          "id": true
        },
        "before_sensitive": {},
        "after_sensitive": {},
        "replace_paths": [
          [
            "triggers"
          ]
        ]
      },
      "action_reason": "replace_because_cannot_update"
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
