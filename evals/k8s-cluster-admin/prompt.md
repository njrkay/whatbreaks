---
name: k8s-cluster-admin
description: "RBAC change to unblock the dev team. Review before apply."
tags: ["kubernetes", "iam"]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]
---

RBAC change to unblock the dev team. Review before apply.

This is the output of `terraform show -json tfplan`:

```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.8",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "kubernetes_cluster_role_binding.everyone",
          "mode": "managed",
          "type": "kubernetes_cluster_role_binding",
          "name": "everyone",
          "provider_name": "registry.terraform.io/hashicorp/kubernetes",
          "schema_version": 0,
          "values": {
            "metadata": [
              {
                "name": "everyone-admin"
              }
            ],
            "role_ref": [
              {
                "api_group": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "cluster-admin"
              }
            ],
            "subject": [
              {
                "api_group": "rbac.authorization.k8s.io",
                "kind": "Group",
                "name": "system:authenticated"
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
      "address": "kubernetes_cluster_role_binding.everyone",
      "mode": "managed",
      "type": "kubernetes_cluster_role_binding",
      "name": "everyone",
      "provider_name": "registry.terraform.io/hashicorp/kubernetes",
      "change": {
        "actions": [
          "create"
        ],
        "before": null,
        "after": {
          "metadata": [
            {
              "name": "everyone-admin"
            }
          ],
          "role_ref": [
            {
              "api_group": "rbac.authorization.k8s.io",
              "kind": "ClusterRole",
              "name": "cluster-admin"
            }
          ],
          "subject": [
            {
              "api_group": "rbac.authorization.k8s.io",
              "kind": "Group",
              "name": "system:authenticated"
            }
          ]
        },
        "after_unknown": {
          "metadata": [
            {}
          ],
          "role_ref": [
            {}
          ],
          "subject": [
            {}
          ],
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
