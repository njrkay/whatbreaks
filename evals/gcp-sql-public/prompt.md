---
name: gcp-sql-public
description: "Reviewing a teammate's GCP change: a firewall rule and a Cloud SQL network update. What breaks?"
tags: ["gcp", "exposure"]
max_turns: 15
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]
---

Reviewing a teammate's GCP change: a firewall rule and a Cloud SQL network update. What breaks?

This is the output of `terraform show -json tfplan`:

```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.8",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "google_compute_firewall.allow_admin",
          "mode": "managed",
          "type": "google_compute_firewall",
          "name": "allow_admin",
          "provider_name": "registry.terraform.io/hashicorp/google",
          "schema_version": 0,
          "values": {
            "name": "allow-admin",
            "network": "default",
            "direction": "INGRESS",
            "disabled": false,
            "source_ranges": [
              "0.0.0.0/0"
            ],
            "allow": [
              {
                "protocol": "tcp",
                "ports": [
                  "22"
                ]
              }
            ],
            "deny": []
          },
          "sensitive_values": {}
        },
        {
          "address": "google_sql_database_instance.main",
          "mode": "managed",
          "type": "google_sql_database_instance",
          "name": "main",
          "provider_name": "registry.terraform.io/hashicorp/google",
          "schema_version": 0,
          "values": {
            "id": "main",
            "name": "main",
            "database_version": "POSTGRES_16",
            "deletion_protection": true,
            "settings": [
              {
                "tier": "db-custom-2-7680",
                "ip_configuration": [
                  {
                    "ipv4_enabled": true,
                    "authorized_networks": [
                      {
                        "name": "office",
                        "value": "203.0.113.0/24"
                      },
                      {
                        "name": "anywhere",
                        "value": "0.0.0.0/0"
                      }
                    ]
                  }
                ]
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
      "address": "google_compute_firewall.allow_admin",
      "mode": "managed",
      "type": "google_compute_firewall",
      "name": "allow_admin",
      "provider_name": "registry.terraform.io/hashicorp/google",
      "change": {
        "actions": [
          "create"
        ],
        "before": null,
        "after": {
          "name": "allow-admin",
          "network": "default",
          "direction": "INGRESS",
          "disabled": false,
          "source_ranges": [
            "0.0.0.0/0"
          ],
          "allow": [
            {
              "protocol": "tcp",
              "ports": [
                "22"
              ]
            }
          ],
          "deny": []
        },
        "after_unknown": {
          "source_ranges": [
            false
          ],
          "allow": [
            {
              "ports": [
                false
              ]
            }
          ],
          "deny": [],
          "id": true
        },
        "before_sensitive": false,
        "after_sensitive": {}
      }
    },
    {
      "address": "google_sql_database_instance.main",
      "mode": "managed",
      "type": "google_sql_database_instance",
      "name": "main",
      "provider_name": "registry.terraform.io/hashicorp/google",
      "change": {
        "actions": [
          "update"
        ],
        "before": {
          "id": "main",
          "name": "main",
          "database_version": "POSTGRES_16",
          "deletion_protection": true,
          "settings": [
            {
              "tier": "db-custom-2-7680",
              "ip_configuration": [
                {
                  "ipv4_enabled": true,
                  "authorized_networks": []
                }
              ]
            }
          ]
        },
        "after": {
          "id": "main",
          "name": "main",
          "database_version": "POSTGRES_16",
          "deletion_protection": true,
          "settings": [
            {
              "tier": "db-custom-2-7680",
              "ip_configuration": [
                {
                  "ipv4_enabled": true,
                  "authorized_networks": [
                    {
                      "name": "office",
                      "value": "203.0.113.0/24"
                    },
                    {
                      "name": "anywhere",
                      "value": "0.0.0.0/0"
                    }
                  ]
                }
              ]
            }
          ]
        },
        "after_unknown": {
          "settings": [
            {
              "ip_configuration": [
                {
                  "authorized_networks": [
                    {},
                    {}
                  ]
                }
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
