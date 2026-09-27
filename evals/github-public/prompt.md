---
name: github-public
description: "Making the platform repo public. Plan attached."
tags: ["github", "exposure"]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]
---

Making the platform repo public. Plan attached.

This is the output of `terraform show -json tfplan`:

```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.8",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "github_repository.platform",
          "mode": "managed",
          "type": "github_repository",
          "name": "platform",
          "provider_name": "registry.terraform.io/integrations/github",
          "schema_version": 0,
          "values": {
            "id": "platform",
            "name": "platform",
            "visibility": "public",
            "private": false
          },
          "sensitive_values": {}
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "github_repository.platform",
      "mode": "managed",
      "type": "github_repository",
      "name": "platform",
      "provider_name": "registry.terraform.io/integrations/github",
      "change": {
        "actions": [
          "update"
        ],
        "before": {
          "id": "platform",
          "name": "platform",
          "visibility": "private",
          "private": true
        },
        "after": {
          "id": "platform",
          "name": "platform",
          "visibility": "public",
          "private": false
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
