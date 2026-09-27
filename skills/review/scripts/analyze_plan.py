#!/usr/bin/env python3
"""whatbreaks — deterministic risk analysis of a Terraform / OpenTofu plan.

Reads the JSON produced by `terraform show -json <planfile>` (or `tofu show -json`)
and reports what the apply would destroy, replace, expose, or weaken, ranked by
severity, with a concrete fix for each finding.

Standard library only. No network access. Never prints values the plan marks
as sensitive.

Usage:
  analyze_plan.py plan.json                      # markdown report to stdout
  analyze_plan.py plan.json --format json        # machine-readable report
  analyze_plan.py - < plan.json                  # read from stdin
  analyze_plan.py plan.json --plan-file tfplan --marker-dir DIR
                                                 # also record a review marker keyed by
                                                 # sha256(tfplan) so the apply gate hook
                                                 # can recognise the reviewed plan
  analyze_plan.py plan.json --exit-code          # exit 2 on BLOCK, 1 on WARN, 0 otherwise

Exit status is 0 unless --exit-code is given or the input can't be read.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys
from typing import Any, Iterable

VERSION = "0.1.0"

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# --------------------------------------------------------------------------- #
# Resource catalogs                                                             #
# --------------------------------------------------------------------------- #
# Tier "data": destroying or replacing loses stored data (or backups, or keys
# that data is encrypted with). Delete/replace => CRITICAL.
DATA_TYPES = {
    # AWS
    "aws_db_instance", "aws_rds_cluster", "aws_rds_global_cluster", "aws_dynamodb_table",
    "aws_dynamodb_global_table", "aws_s3_bucket", "aws_s3_directory_bucket", "aws_ebs_volume",
    "aws_efs_file_system", "aws_fsx_lustre_file_system", "aws_fsx_windows_file_system",
    "aws_fsx_ontap_file_system", "aws_fsx_openzfs_file_system", "aws_elasticache_cluster",
    "aws_elasticache_replication_group", "aws_elasticache_serverless_cache", "aws_memorydb_cluster",
    "aws_redshift_cluster", "aws_redshiftserverless_namespace", "aws_opensearch_domain",
    "aws_elasticsearch_domain", "aws_opensearchserverless_collection", "aws_docdb_cluster",
    "aws_neptune_cluster", "aws_kms_key", "aws_kms_external_key", "aws_secretsmanager_secret",
    "aws_backup_vault", "aws_glacier_vault", "aws_msk_cluster", "aws_msk_serverless_cluster",
    "aws_cognito_user_pool", "aws_cognito_identity_pool", "aws_timestreamwrite_table",
    "aws_timestreamwrite_database", "aws_keyspaces_table", "aws_keyspaces_keyspace",
    "aws_qldb_ledger", "aws_dax_cluster", "aws_lightsail_database", "aws_db_snapshot",
    "aws_ebs_snapshot", "aws_rds_cluster_snapshot", "aws_backup_plan", "aws_backup_selection",
    "aws_organizations_account", "aws_lightsail_disk", "aws_route53_zone",
    "aws_acmpca_certificate_authority", "aws_cloudhsm_v2_cluster", "aws_workspaces_directory",
    "aws_storagegateway_gateway", "aws_datasync_task", "aws_finspace_kx_environment",
    # GCP
    "google_sql_database_instance", "google_sql_database", "google_storage_bucket",
    "google_bigquery_dataset", "google_bigquery_table", "google_spanner_instance",
    "google_spanner_database", "google_bigtable_instance", "google_bigtable_table",
    "google_firestore_database", "google_compute_disk", "google_compute_region_disk",
    "google_filestore_instance", "google_alloydb_cluster", "google_alloydb_instance",
    "google_secret_manager_secret", "google_kms_crypto_key", "google_kms_key_ring",
    "google_project", "google_dns_managed_zone", "google_memorystore_instance",
    "google_redis_cluster", "google_redis_instance", "google_artifact_registry_repository",
    # Azure
    "azurerm_mssql_database", "azurerm_mssql_server", "azurerm_mssql_managed_instance",
    "azurerm_postgresql_flexible_server", "azurerm_postgresql_server", "azurerm_mysql_flexible_server",
    "azurerm_mysql_server", "azurerm_mariadb_server", "azurerm_cosmosdb_account",
    "azurerm_cosmosdb_sql_database", "azurerm_cosmosdb_mongo_database", "azurerm_storage_account",
    "azurerm_storage_container", "azurerm_storage_share", "azurerm_managed_disk",
    "azurerm_key_vault", "azurerm_recovery_services_vault", "azurerm_resource_group",
    "azurerm_synapse_workspace", "azurerm_log_analytics_workspace", "azurerm_dns_zone",
    "azurerm_private_dns_zone", "azurerm_container_registry", "azurerm_redis_cache",
    "azurerm_netapp_volume", "azurerm_kusto_cluster", "azurerm_data_lake_store",
    # Kubernetes / Helm
    "kubernetes_persistent_volume_claim", "kubernetes_persistent_volume", "kubernetes_namespace",
    "kubernetes_persistent_volume_claim_v1", "kubernetes_persistent_volume_v1",
    "kubernetes_namespace_v1",
    # Other providers
    "mongodbatlas_cluster", "mongodbatlas_advanced_cluster", "snowflake_database",
    "snowflake_schema", "snowflake_table", "vault_mount", "vault_kv_secret_v2",
    "vault_kv_secret", "github_repository", "github_organization", "gitlab_project",
    "digitalocean_database_cluster", "digitalocean_volume", "digitalocean_spaces_bucket",
    "hcloud_volume", "linode_volume", "cloudflare_zone", "cloudflare_r2_bucket",
    "cloudflare_d1_database", "planetscale_database", "neon_project", "supabase_project",
    "confluent_kafka_cluster", "confluent_kafka_topic", "elasticstack_elasticsearch_index",
    "postgresql_database", "mysql_database", "mssql_database", "vsphere_datastore_cluster",
}

# Tier "outage": destroying or replacing causes downtime, changes public
# endpoints/IPs, or removes a control (audit, protection). Delete/replace => HIGH.
OUTAGE_TYPES = {
    # AWS
    "aws_rds_cluster_instance", "aws_instance", "aws_spot_instance_request", "aws_eks_cluster",
    "aws_eks_node_group", "aws_eks_fargate_profile", "aws_ecs_cluster", "aws_ecs_service",
    "aws_lb", "aws_alb", "aws_elb", "aws_lb_listener", "aws_nat_gateway", "aws_vpc", "aws_subnet",
    "aws_internet_gateway", "aws_vpn_connection", "aws_vpn_gateway", "aws_dx_connection",
    "aws_dx_gateway", "aws_ec2_transit_gateway", "aws_ec2_transit_gateway_attachment",
    "aws_eip", "aws_autoscaling_group", "aws_cloudfront_distribution", "aws_api_gateway_rest_api",
    "aws_apigatewayv2_api", "aws_api_gateway_domain_name", "aws_apigatewayv2_domain_name",
    "aws_route53_record", "aws_route53_health_check", "aws_acm_certificate", "aws_cloudtrail",
    "aws_config_configuration_recorder", "aws_guardduty_detector", "aws_securityhub_account",
    "aws_wafv2_web_acl", "aws_waf_web_acl", "aws_shield_protection", "aws_ecr_repository",
    "aws_ecr_public_repository", "aws_transfer_server", "aws_globalaccelerator_accelerator",
    "aws_directory_service_directory", "aws_organizations_organizational_unit",
    "aws_organizations_policy", "aws_organizations_policy_attachment", "aws_iam_role",
    "aws_iam_user", "aws_iam_instance_profile", "aws_iam_openid_connect_provider",
    "aws_iam_saml_provider", "aws_kms_alias", "aws_kinesis_stream", "aws_kinesis_firehose_delivery_stream",
    "aws_sqs_queue", "aws_sns_topic", "aws_sfn_state_machine", "aws_mq_broker",
    "aws_cloudwatch_log_group", "aws_flow_log", "aws_glue_catalog_database",
    "aws_glue_catalog_table", "aws_sagemaker_endpoint", "aws_sagemaker_domain",
    "aws_workspaces_workspace", "aws_appsync_graphql_api", "aws_amplify_app", "aws_lambda_function",
    "aws_db_subnet_group", "aws_elasticache_subnet_group",
    "aws_db_parameter_group", "aws_rds_cluster_parameter_group", "aws_security_group",
    "aws_network_acl", "aws_route_table", "aws_route", "aws_vpc_peering_connection",
    "aws_vpc_endpoint", "aws_efs_mount_target", "aws_codecommit_repository",
    "aws_codepipeline", "aws_service_discovery_service",
    "aws_lightsail_instance", "aws_batch_compute_environment", "aws_emr_cluster",
    "aws_bedrock_custom_model", "aws_bedrockagent_agent", "aws_bedrockagent_knowledge_base",
    # GCP
    "google_container_cluster", "google_container_node_pool", "google_compute_instance",
    "google_compute_instance_group_manager", "google_compute_region_instance_group_manager",
    "google_compute_network", "google_compute_subnetwork", "google_compute_address",
    "google_compute_global_address", "google_compute_forwarding_rule",
    "google_compute_global_forwarding_rule", "google_compute_router", "google_compute_router_nat",
    "google_compute_vpn_gateway", "google_compute_ha_vpn_gateway", "google_compute_ssl_certificate",
    "google_compute_managed_ssl_certificate", "google_cloud_run_service", "google_cloud_run_v2_service",
    "google_cloudfunctions_function", "google_cloudfunctions2_function", "google_pubsub_topic",
    "google_pubsub_subscription", "google_logging_project_sink", "google_logging_organization_sink",
    "google_folder", "google_service_account", "google_dataproc_cluster", "google_composer_environment",
    "google_compute_firewall", "google_dns_record_set", "google_secret_manager_secret_version",
    "google_project_service", "google_kms_crypto_key_version", "google_app_engine_application",
    "google_compute_security_policy", "google_iam_workload_identity_pool",
    "google_iam_workload_identity_pool_provider", "google_project_iam_audit_config",
    "google_memcache_instance", "google_vertex_ai_endpoint", "google_dataflow_job",
    # Azure
    "azurerm_kubernetes_cluster", "azurerm_kubernetes_cluster_node_pool", "azurerm_virtual_machine",
    "azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine",
    "azurerm_linux_virtual_machine_scale_set", "azurerm_windows_virtual_machine_scale_set",
    "azurerm_virtual_network", "azurerm_subnet", "azurerm_public_ip", "azurerm_nat_gateway",
    "azurerm_virtual_network_gateway", "azurerm_express_route_circuit", "azurerm_application_gateway",
    "azurerm_lb", "azurerm_firewall", "azurerm_front_door", "azurerm_cdn_frontdoor_profile",
    "azurerm_network_security_group", "azurerm_key_vault_key", "azurerm_key_vault_certificate", "azurerm_databricks_workspace", "azurerm_data_factory",
    "azurerm_backup_protected_vm", "azurerm_backup_policy_vm", "azurerm_eventhub_namespace",
    "azurerm_servicebus_namespace", "azurerm_app_service", "azurerm_linux_web_app",
    "azurerm_windows_web_app", "azurerm_linux_function_app", "azurerm_windows_function_app",
    "azurerm_function_app", "azurerm_container_app", "azurerm_container_app_environment",
    "azurerm_role_assignment", "azurerm_role_definition", "azurerm_user_assigned_identity",
    "azurerm_monitor_diagnostic_setting", "azurerm_policy_assignment",
    "azurerm_management_group", "azurerm_dns_a_record", "azurerm_dns_cname_record",
    "azurerm_private_endpoint", "azurerm_api_management", "azurerm_signalr_service",
    # Kubernetes / Helm
    "kubernetes_stateful_set", "kubernetes_stateful_set_v1", "helm_release", "kubernetes_deployment",
    "kubernetes_deployment_v1", "kubernetes_service", "kubernetes_service_v1", "kubernetes_ingress",
    "kubernetes_ingress_v1", "kubernetes_secret", "kubernetes_secret_v1", "kubernetes_daemonset",
    "kubernetes_daemon_set_v1", "kubernetes_cluster_role_binding", "kubernetes_network_policy",
    # Other
    "cloudflare_record", "cloudflare_dns_record", "cloudflare_worker_script", "cloudflare_tunnel",
    "cloudflare_zero_trust_tunnel_cloudflared", "github_branch_protection", "github_repository_ruleset",
    "github_team", "datadog_monitor", "datadog_synthetics_test", "pagerduty_service",
    "pagerduty_escalation_policy", "digitalocean_droplet", "digitalocean_kubernetes_cluster",
    "digitalocean_loadbalancer", "linode_instance", "hcloud_server", "proxmox_vm_qemu",
    "vsphere_virtual_machine", "okta_app_oauth", "okta_group", "auth0_client", "auth0_tenant",
    "vault_auth_backend", "vault_policy", "vault_generic_secret", "tfe_workspace",
    "newrelic_alert_policy", "grafana_dashboard", "opsgenie_service",
}

# Tier "trivial": recreation is cheap and carries no state. Delete/replace => LOW.
TRIVIAL_TYPES = {
    "null_resource", "terraform_data", "local_file", "local_sensitive_file", "random_id",
    "random_string", "random_pet", "random_integer", "random_uuid", "random_shuffle",
    "time_sleep", "time_static", "time_offset", "time_rotating", "aws_ec2_tag",
    "aws_lb_listener_certificate",
    "aws_cloudwatch_dashboard",
}
# Tier "versioned": a replace creates a new revision/version and retires the old one; this is
# how these resources are meant to change. Replace => LOW; delete => MEDIUM (default tier).
VERSIONED_TYPES = {
    "aws_ecs_task_definition", "aws_secretsmanager_secret_version", "google_secret_manager_secret_version",
    "aws_launch_template", "aws_ssm_document", "aws_lambda_layer_version",
    "aws_ssm_parameter", "azurerm_key_vault_secret", "aws_lambda_alias", "aws_appconfig_hosted_configuration_version",
    "google_cloud_run_v2_service_iam_binding", "aws_batch_job_definition", "aws_imagebuilder_image",
    "aws_sagemaker_model", "aws_api_gateway_deployment", "aws_apigatewayv2_deployment",
}
TRIVIAL_PREFIXES = ("random_", "time_", "local_", "tls_", "archive_", "external_", "http_")

# Heuristics for resource types absent from the catalogs above. Matched on whole
# underscore-delimited tokens after the provider prefix, so "aws_route_table_association"
# is not "table" and "vault_token" is not "vault".
HEURISTIC_DATA_WORDS = {
    "database", "db", "bucket", "volume", "disk", "table", "snapshot", "backup", "filesystem",
    "ledger", "spanner", "bigtable", "firestore", "dynamodb", "keyspace", "datastore", "kms",
    "cache", "warehouse", "index", "collection",
}
HEURISTIC_DATA_PHRASES = ("file_system", "storage_account", "kms_key", "crypto_key", "key_ring", "user_pool")
HEURISTIC_OUTAGE_WORDS = {
    "cluster", "instance", "zone", "gateway", "vpc", "network", "subnet", "address", "eip",
    "certificate", "registry", "repository", "secret", "function", "service", "deployment",
    "distribution", "domain", "endpoint", "queue", "topic", "stream", "identity", "role",
    "firewall", "lb", "api", "server", "vm", "app", "job", "pipeline", "workspace", "project",
}
HEURISTIC_OUTAGE_PHRASES = ("node_pool", "node_group", "load_balancer", "security_group", "stateful_set")
# Sub-resources: settings attached to something else. Deleting them is a MEDIUM (default)
# change, never a data-loss CRITICAL, whatever their parent's name says.
SUBRESOURCE_SUFFIXES = (
    "_policy", "_iam_member", "_iam_binding", "_iam_policy", "_association", "_attachment",
    "_configuration", "_notification", "_rule", "_rules", "_access_policy", "_subnet_group",
    "_option_group", "_parameter_group", "_event_subscription", "_acl", "_cors_configuration",
    "_logging", "_metric", "_versioning", "_website_configuration", "_ownership_controls",
    "_target", "_lifecycle_configuration", "_tag", "_tags", "_label", "_labels", "_setting",
    "_settings", "_route", "_mapping", "_permission", "_permissions", "_assignment", "_member",
    "_membership", "_binding", "_alias", "_grant", "_sink", "_export", "_condition",
)

# Attributes whose change from true->false (or false->true) removes a safety mechanism.
# (attribute name, "safe value", human label, severity, fix)
PROTECTION_FLAGS = [
    ("deletion_protection", True, "deletion protection", "HIGH",
     "Keep `deletion_protection = true` unless you intend to delete this resource in a later "
     "apply. Turning it off is the first step of a deletion."),
    ("deletion_protection_enabled", True, "deletion protection", "HIGH",
     "Keep `deletion_protection_enabled = true` unless deletion is intended."),
    ("enable_deletion_protection", True, "deletion protection", "HIGH",
     "Keep `enable_deletion_protection = true` unless deletion is intended."),
    ("prevent_destroy", True, "prevent_destroy", "HIGH",
     "Keep `prevent_destroy` enabled."),
    ("skip_final_snapshot", False, "final snapshot on delete", "HIGH",
     "Set `skip_final_snapshot = false` and a `final_snapshot_identifier` so a deletion leaves "
     "a restorable snapshot behind."),
    ("force_destroy", False, "force_destroy guard", "HIGH",
     "Keep `force_destroy = false`; with it on, a future destroy deletes all contents without "
     "asking."),
    ("force_delete", False, "force_delete guard", "MEDIUM",
     "Keep `force_delete = false` unless you intend to remove contents."),
    ("enable_key_rotation", True, "KMS key rotation", "LOW",
     "Keep `enable_key_rotation = true`."),
    ("storage_encrypted", True, "storage encryption", "HIGH",
     "Keep `storage_encrypted = true`. Note that changing it forces replacement on most engines."),
    ("encrypted", True, "encryption at rest", "HIGH",
     "Keep `encrypted = true`."),
    ("kms_key_enabled", True, "KMS encryption", "HIGH", "Keep KMS encryption enabled."),
    ("enable_logging", True, "logging", "HIGH",
     "Keep `enable_logging = true`; disabling it blinds audit/detection."),
    ("logging_enabled", True, "logging", "MEDIUM", "Keep logging enabled."),
    ("enable_log_file_validation", True, "CloudTrail log file validation", "MEDIUM",
     "Keep log file validation on so tampering with audit logs is detectable."),
    ("is_multi_region_trail", True, "multi-region trail", "MEDIUM",
     "Keep the trail multi-region so activity in other regions is still recorded."),
    ("multi_az", True, "Multi-AZ", "MEDIUM",
     "Keep `multi_az = true` for production databases; single-AZ removes automatic failover."),
    ("copy_tags_to_snapshot", True, "snapshot tagging", "LOW", "Keep tags on snapshots."),
    ("auto_minor_version_upgrade", True, "auto minor version upgrade", "LOW",
     "Consider keeping automatic minor upgrades on for security patches."),
    ("mfa_delete", True, "MFA delete", "MEDIUM", "Keep MFA delete enabled."),
    ("purge_protection_enabled", True, "purge protection", "HIGH",
     "Keep `purge_protection_enabled = true`; without it a deleted vault/key can be purged "
     "before the soft-delete window ends."),
    ("soft_delete_enabled", True, "soft delete", "HIGH", "Keep soft delete enabled."),
    ("enable_rbac_authorization", True, "RBAC authorization", "MEDIUM", "Keep RBAC on."),
    ("https_traffic_only_enabled", True, "HTTPS-only", "HIGH", "Keep HTTPS-only enforced."),
    ("enable_https_traffic_only", True, "HTTPS-only", "HIGH", "Keep HTTPS-only enforced."),
    ("min_tls_version", None, None, None, None),  # handled separately
    ("block_public_acls", True, "public ACL blocking", "HIGH",
     "Keep `block_public_acls = true` unless the bucket is meant to be public."),
    ("block_public_policy", True, "public policy blocking", "HIGH",
     "Keep `block_public_policy = true` unless the bucket is meant to be public."),
    ("ignore_public_acls", True, "public ACL ignoring", "HIGH",
     "Keep `ignore_public_acls = true` unless the bucket is meant to be public."),
    ("restrict_public_buckets", True, "public bucket restriction", "HIGH",
     "Keep `restrict_public_buckets = true` unless the bucket is meant to be public."),
]
# Security controls whose on/off switch has a type-specific attribute name.
# (type suffix, attribute, safe value, severity, label)
CONTROL_TOGGLES = [
    ("aws_guardduty_detector", "enable", True, "HIGH", "GuardDuty detector"),
    ("aws_config_configuration_recorder_status", "is_enabled", True, "HIGH", "AWS Config recorder"),
    ("aws_macie2_account", "status", "ENABLED", "HIGH", "Macie"),
    ("aws_securityhub_standards_control", "control_status", "ENABLED", "MEDIUM", "Security Hub control"),
    ("aws_accessanalyzer_analyzer", None, None, None, None),
    ("aws_cloudwatch_metric_alarm", "actions_enabled", True, "MEDIUM", "alarm actions"),
    ("aws_cloudwatch_event_rule", "state", "ENABLED", "LOW", "EventBridge rule"),
    ("aws_cloudwatch_event_rule", "is_enabled", True, "LOW", "EventBridge rule"),
    ("aws_inspector2_enabler", None, None, None, None),
    ("aws_ebs_encryption_by_default", "enabled", True, "HIGH", "EBS encryption by default"),
    ("aws_s3_account_public_access_block", None, None, None, None),  # covered by block_public_* flags
    ("google_project_service", "disable_on_destroy", None, None, None),
    ("google_compute_firewall", "disabled", False, "MEDIUM", "firewall rule"),
    ("azurerm_security_center_subscription_pricing", "tier", "Standard", "MEDIUM", "Defender for Cloud plan"),
    ("azurerm_monitor_diagnostic_setting", None, None, None, None),
    ("datadog_monitor", "enable_logs_sample", None, None, None),
]

PIT_RECOVERY_KEYS = ("point_in_time_recovery",)

ADMIN_POLICY_SUFFIXES = ("/AdministratorAccess", "/IAMFullAccess")
BROAD_POLICY_MARKERS = ("PowerUserAccess", "FullAccess", "AdministratorAccess-")

ESCALATION_ACTIONS = {
    "iam:createpolicyversion", "iam:setdefaultpolicyversion", "iam:attachrolepolicy",
    "iam:putrolepolicy", "iam:attachuserpolicy", "iam:putuserpolicy", "iam:attachgrouppolicy",
    "iam:putgrouppolicy", "iam:createpolicy", "iam:updateassumerolepolicy",
    "iam:createaccesskey", "iam:createloginprofile", "iam:updateloginprofile",
    "iam:addusertogroup", "iam:deleterolepermissionsboundary",
    "iam:deleteuserpermissionsboundary", "iam:putrolepermissionsboundary",
    "iam:putuserpermissionsboundary", "lambda:updatefunctioncode", "lambda:createfunction",
    "glue:updatedevendpoint", "cloudformation:createstack", "sts:assumerole",
}

ADMIN_PORTS = {
    21: "FTP", 22: "secure shell", 23: "Telnet", 25: "SMTP", 135: "RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 1434: "MSSQL", 1521: "Oracle", 2049: "NFS",
    2181: "ZooKeeper", 2375: "Docker", 2376: "Docker", 2379: "etcd", 2380: "etcd",
    3306: "MySQL", 3389: "RDP", 4505: "Salt", 4506: "Salt", 5432: "PostgreSQL", 5601: "Kibana",
    5900: "VNC", 5984: "CouchDB", 5985: "WinRM", 5986: "WinRM", 6379: "Redis", 6443: "Kubernetes API",
    7000: "Cassandra", 7001: "Cassandra", 8020: "HDFS",
    8500: "Consul", 9000: "HDFS/MinIO", 9042: "Cassandra", 9092: "Kafka", 9200: "Elasticsearch",
    9300: "Elasticsearch", 10250: "kubelet", 11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB",
    50070: "Hadoop",
}
WEB_PORTS = {80, 443}
ALT_WEB_PORTS = {8080, 8443, 8000, 8888, 3000}

OPEN_CIDRS = {"0.0.0.0/0", "::/0", "*", "internet", "any"}

GCP_ADMIN_ROLES = {"roles/owner": "CRITICAL", "roles/editor": "HIGH", "roles/iam.securityAdmin": "HIGH",
                   "roles/resourcemanager.projectIamAdmin": "HIGH",
                   "roles/resourcemanager.organizationAdmin": "CRITICAL",
                   "roles/iam.serviceAccountTokenCreator": "HIGH",
                   "roles/iam.serviceAccountUser": "HIGH", "roles/iam.serviceAccountAdmin": "HIGH",
                   "roles/iam.serviceAccountKeyAdmin": "HIGH", "roles/storage.admin": "MEDIUM",
                   "roles/compute.admin": "MEDIUM", "roles/container.admin": "MEDIUM",
                   "roles/cloudsql.admin": "MEDIUM", "roles/secretmanager.admin": "HIGH"}
AZURE_ROLE_GUIDS = {"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "owner",
                    "b24988ac-6180-42a0-ab88-20f7382dd24c": "contributor",
                    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "user access administrator",
                    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "role based access control administrator"}
AZURE_ADMIN_ROLES = {"owner": "CRITICAL", "user access administrator": "CRITICAL",
                     "contributor": "HIGH", "role based access control administrator": "CRITICAL",
                     "security admin": "HIGH", "key vault administrator": "HIGH",
                     "storage account contributor": "MEDIUM", "virtual machine contributor": "MEDIUM"}


# --------------------------------------------------------------------------- #
# Model                                                                         #
# --------------------------------------------------------------------------- #
class Finding:
    __slots__ = ("rule", "severity", "category", "address", "rtype", "action", "title",
                 "detail", "fix", "evidence")

    def __init__(self, rule: str, severity: str, category: str, address: str, rtype: str,
                 action: str, title: str, detail: str, fix: str, evidence: dict | None = None):
        assert severity in SEV_RANK, severity
        self.rule = rule
        self.severity = severity
        self.category = category
        self.address = address
        self.rtype = rtype
        self.action = action
        self.title = title
        self.detail = detail
        self.fix = fix
        self.evidence = evidence or {}

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


class Change:
    """One entry of resource_changes, with helpers."""

    def __init__(self, raw: dict):
        self.raw = raw
        self.address: str = str(raw.get("address") or "?")
        self.mode: str = str(raw.get("mode") or "managed")
        self.type: str = str(raw.get("type") or "")
        self.name: str = str(raw.get("name") or "")
        self.provider: str = str(raw.get("provider_name") or "")
        self.deposed: str | None = raw.get("deposed")
        ch = raw.get("change")
        if not isinstance(ch, dict):
            ch = {}
        self.actions: list[str] = [str(a) for a in (ch.get("actions") or []) if a is not None]
        self.before: Any = ch.get("before")
        self.after: Any = ch.get("after")
        self.after_unknown: Any = ch.get("after_unknown") or {}
        self.before_sensitive: Any = ch.get("before_sensitive") or {}
        self.after_sensitive: Any = ch.get("after_sensitive") or {}
        rp = ch.get("replace_paths") or []
        self.replace_paths: list = [p if isinstance(p, list) else [p] for p in rp] if isinstance(rp, list) else []
        self.importing: Any = ch.get("importing")
        self.action_reason: str = str(raw.get("action_reason") or "")
        self.rename_to: str | None = None  # filled by the rename pre-pass in analyze()

    @property
    def kind(self) -> str:
        a = self.actions
        if a == ["no-op"] or not a:
            return "no-op"
        if a == ["create"]:
            return "create"
        if a == ["update"]:
            return "update"
        if a == ["delete"]:
            return "delete"
        if a == ["read"]:
            return "read"
        if a == ["forget"]:
            return "forget"
        if "delete" in a and "create" in a:
            return "replace"
        return "+".join(a)

    @property
    def create_before_destroy(self) -> bool:
        return self.actions[:2] == ["create", "delete"]

    def before_get(self, key: str, default=None):
        if isinstance(self.before, dict):
            return self.before.get(key, default)
        return default

    def after_get(self, key: str, default=None):
        if isinstance(self.after, dict):
            return self.after.get(key, default)
        return default

    def is_unknown(self, key: str) -> bool:
        """True only when the top-level attribute itself is unknown until apply.

        Terraform's after_unknown keeps collection *structure* for known values
        (e.g. ``"inline_policy": [{}]`` or ``"managed_policy_arns": [false, false]``),
        so a non-empty list or dict does NOT mean the attribute is unknown.
        """
        au = self.after_unknown
        return isinstance(au, dict) and au.get(key) is True

    def path_unknown(self, path: list) -> bool:
        """Walk a replace_paths-style path into after_unknown; True only at a literal true."""
        node: Any = self.after_unknown
        for step in path:
            if isinstance(node, dict):
                node = node.get(str(step))
            elif isinstance(node, list):
                try:
                    node = node[int(step)]
                except (ValueError, IndexError, TypeError):
                    return False
            else:
                return node is True
        return node is True

    def is_sensitive(self, key: str, side: str = "after") -> bool:
        m = self.after_sensitive if side == "after" else self.before_sensitive
        if isinstance(m, dict):
            v = m.get(key)
            return bool(v) if not isinstance(v, (dict, list)) else _any_true(v)
        return False


def _any_true(v: Any) -> bool:
    if v is True:
        return True
    if isinstance(v, dict):
        return any(_any_true(x) for x in v.values())
    if isinstance(v, list):
        return any(_any_true(x) for x in v)
    return False


def masked(ch: Change, key: str, side: str = "after") -> Any:
    """Return a value safe to print: sensitive values are replaced."""
    if ch.is_sensitive(key, side):
        return "«sensitive»"
    v = ch.after_get(key) if side == "after" else ch.before_get(key)
    return _shorten(v)


def hcl(v: Any) -> str:
    """Render a value the way it appears in HCL (true/false/null), for messages."""
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    return str(_shorten(v))


def _shorten(v: Any, limit: int = 120) -> Any:
    if isinstance(v, str) and len(v) > limit:
        return v[:limit] + "…"
    if isinstance(v, (dict, list)):
        s = json.dumps(v, sort_keys=True)
        return s if len(s) <= limit else s[:limit] + "…"
    return v


# --------------------------------------------------------------------------- #
# Type classification                                                           #
# --------------------------------------------------------------------------- #
def classify_type(rtype: str) -> str:
    """Return 'data', 'outage', 'versioned', 'trivial', or 'default' for a resource type."""
    if rtype in DATA_TYPES:
        return "data"
    if rtype in OUTAGE_TYPES:
        return "outage"
    if rtype in VERSIONED_TYPES:
        return "versioned"
    if rtype in TRIVIAL_TYPES or rtype.startswith(TRIVIAL_PREFIXES):
        return "trivial"
    low = rtype.lower()
    if low.endswith(SUBRESOURCE_SUFFIXES):
        return "default"
    parts = low.split("_")
    body = "_".join(parts[1:]) if len(parts) > 1 else low   # drop the provider prefix
    tokens = set(body.split("_"))
    if tokens & HEURISTIC_DATA_WORDS or any(p in body for p in HEURISTIC_DATA_PHRASES):
        return "data"
    if tokens & HEURISTIC_OUTAGE_WORDS or any(p in body for p in HEURISTIC_OUTAGE_PHRASES):
        return "outage"
    return "default"


TIER_SEVERITY = {"data": "CRITICAL", "outage": "HIGH", "default": "MEDIUM", "versioned": "MEDIUM", "trivial": "LOW"}
TIER_LABEL = {
    "data": "holds data (or keys/backups protecting data)",
    "outage": "is a live endpoint, control, or dependency; recreating it causes downtime or changes identifiers",
    "default": "is not in the catalog; treat as a medium-impact change until confirmed otherwise",
    "versioned": "is revisioned by design; a new version replaces the old one",
    "trivial": "carries no state and is cheap to recreate",
}


# --------------------------------------------------------------------------- #
# Rule: destructive actions                                                     #
# --------------------------------------------------------------------------- #
def _one_lower(sev: str) -> str:
    i = SEV_RANK[sev]
    return SEVERITIES[min(i + 1, len(SEVERITIES) - 1)]


REASON_TEXT = {
    "replace_because_cannot_update": "an attribute that cannot be updated in place changed (ForceNew)",
    "replace_because_tainted": "the resource is tainted",
    "replace_by_request": "replacement was requested with `-replace`",
    "replace_by_triggers": "a `replace_triggered_by` dependency changed",
    "delete_because_no_resource_config": "the resource block was removed from the configuration (or renamed/moved without a `moved` block)",
    "delete_because_wrong_repetition": "the resource switched between count, for_each, and single-instance forms",
    "delete_because_count_index": "the resource's count index no longer exists (count shrank: index >= new count)",
    "delete_because_each_key": "the resource's for_each key no longer exists (map key removed or renamed)",
    "delete_because_no_module": "the enclosing module call was removed",
}


def rule_destructive(ch: Change) -> list[Finding]:
    out: list[Finding] = []
    if ch.mode != "managed":
        return out
    kind = ch.kind
    tier = classify_type(ch.type)
    base = TIER_SEVERITY[tier]

    if kind == "delete":
        reason = REASON_TEXT.get(ch.action_reason, "")
        sev = base
        detail = f"`{ch.address}` ({ch.type}) will be destroyed. This resource type {TIER_LABEL[tier]}."
        if reason:
            detail += f" Terraform's reason: {reason}."
        fix = _delete_fix(ch, tier)
        title = f"Destroy {ch.type}"
        if ch.rename_to:
            # A create of the same type with matching values exists in this plan: almost
            # certainly a rename/move that should be a `moved` block, not a destroy+create.
            title = f"Destroy and recreate {ch.type} (looks like a rename)"
            detail += (f" A `{ch.type}` with the same values is created as `{ch.rename_to}` in this plan, "
                       f"so this looks like a rename or move rather than a removal; as written, the "
                       f"existing object is destroyed and a new empty one created.")
            fix = (f"If this is a rename, add `moved {{ from = {ch.address} / to = {ch.rename_to} }}` "
                   f"(one attribute per line in HCL) and re-plan: the destroy/create pair becomes a no-op "
                   f"and the object keeps its data. Confirm with the user that a rename was the intent; "
                   f"if the old object really should go, take a backup first.")
        if ch.deposed:
            sev = "LOW"
            title = f"Destroy {ch.type} (deposed)"
            detail = f"A deposed (already replaced) object of `{ch.address}` will be cleaned up."
            fix = "No action needed; this removes a leftover object from an earlier create-before-destroy."
        extra = _snapshot_note(ch)
        if extra:
            detail += " " + extra
        out.append(Finding(
            "WB-D001" if not ch.action_reason.startswith("delete_because_") else "WB-D002",
            sev, "destructive", ch.address, ch.type, "delete", title, detail, fix,
            {"action_reason": ch.action_reason, "rename_to": ch.rename_to}))
        return out

    if kind == "replace":
        paths = [_hcl_path(rp) for rp in ch.replace_paths] if ch.replace_paths else []
        reason = REASON_TEXT.get(ch.action_reason, "")
        sev = base
        if tier == "versioned":
            sev = "LOW"
            order = "create a new version and retire the old one"
        elif ch.create_before_destroy:
            order = "create the new one first, then delete the old (create_before_destroy)"
        elif tier == "trivial":
            order = "delete the old one and create a new one"
        else:
            order = "delete the old one first, then create the new one (downtime between the two)"
        detail = (f"`{ch.address}` ({ch.type}) will be REPLACED: Terraform will {order}. "
                  f"This resource type {TIER_LABEL[tier]}.")
        if paths:
            detail += f" Forced by: `{'`, `'.join(paths)}`."
        if reason:
            detail += f" Reason: {reason}."
        unknown_driver = [_hcl_path(rp) for rp in ch.replace_paths if ch.path_unknown(rp)]
        if unknown_driver:
            detail += (f" The new value of `{unknown_driver[0]}` is not known until apply, so the "
                       f"replacement is driven by a computed value.")
        extra = _snapshot_note(ch)
        if extra:
            detail += " " + extra
        fix = _replace_fix(ch, tier, paths)
        out.append(Finding("WB-D003", sev, "destructive", ch.address, ch.type, "replace",
                           f"Replace {ch.type}", detail, fix,
                           {"replace_paths": paths, "action_reason": ch.action_reason,
                            "create_before_destroy": ch.create_before_destroy}))
        return out

    if kind == "forget":
        out.append(Finding("WB-D004", "LOW", "destructive", ch.address, ch.type, "forget",
                           f"Forget {ch.type} (removed from state, not destroyed)",
                           f"`{ch.address}` will be removed from Terraform state but left running "
                           f"(a `removed` block). It becomes unmanaged: no further drift detection, "
                           f"and nothing will ever destroy it through Terraform.",
                           "Confirm that is intended; if you meant to destroy it, delete the "
                           "`removed` block and remove the resource from configuration instead."))
    return out


def _snapshot_note(ch: Change) -> str:
    notes = []
    sfs = ch.before_get("skip_final_snapshot")
    if sfs is True and ch.type in ("aws_db_instance", "aws_rds_cluster", "aws_docdb_cluster",
                                    "aws_neptune_cluster", "aws_redshift_cluster"):
        notes.append("`skip_final_snapshot = true`: NO final snapshot will be taken; the data is gone "
                     "once the delete completes.")
    dp = ch.before_get("deletion_protection")
    if dp is True:
        notes.append("`deletion_protection` is currently on, so this apply will FAIL at this resource "
                     "unless protection is turned off first (which may be what a preceding change does).")
    fd = ch.before_get("force_destroy")
    if fd is True and ch.type in ("aws_s3_bucket", "google_storage_bucket", "aws_ecr_repository"):
        notes.append("`force_destroy = true`: all objects/images inside will be deleted too.")
    brp = ch.before_get("backup_retention_period")
    if isinstance(brp, int) and not isinstance(brp, bool) and brp == 0 and ch.type in ("aws_db_instance", "aws_rds_cluster"):
        notes.append("`backup_retention_period = 0`: there are no automated backups to restore from.")
    if ch.type in ("aws_kms_key", "aws_kms_external_key"):
        win = ch.before_get("deletion_window_in_days")
        notes.append(f"KMS keys are scheduled for deletion, not deleted at once: the key stays recoverable for "
                     f"{win if isinstance(win, int) else 'the configured'} day(s); after that, everything "
                     f"encrypted with it is permanently unreadable.")
    if ch.type in ("aws_secretsmanager_secret",):
        win = ch.before_get("recovery_window_in_days")
        if win == 0:
            notes.append("`recovery_window_in_days = 0`: the secret is deleted immediately with no recovery window.")
    if ch.type in ("kubernetes_namespace", "kubernetes_namespace_v1", "azurerm_resource_group", "google_project"):
        notes.append("Deleting this container deletes EVERYTHING inside it, including resources Terraform does not manage.")
    return " ".join(notes)


def _delete_fix(ch: Change, tier: str) -> str:
    r = ch.action_reason
    if r in ("delete_because_no_resource_config", "delete_because_no_module"):
        return ("If the resource was renamed or moved into/out of a module, add a `moved` block "
                f"(`moved {{ from = {_short_addr(ch.address)} ; to = <new address> }}`) so Terraform "
                "updates the address instead of destroying and recreating. If it should keep running "
                "but leave Terraform's control, use a `removed` block (Terraform >= 1.7) or "
                f"`terraform state rm {ch.address}`. Only proceed with the destroy if the resource is "
                "truly no longer needed.")
    if r in ("delete_because_wrong_repetition", "delete_because_count_index", "delete_because_each_key"):
        return ("This is an index/key shift, not a real removal: the same infrastructure is about to be "
                "destroyed and recreated under a new address. Add `moved` blocks mapping each old "
                f"index/key to its new one (e.g. `moved {{ from = {_short_addr(ch.address)} ; to = "
                "<same resource>[\"<new key>\"] }`), or switch from `count` to `for_each` with stable keys.")
    if tier == "data":
        return ("Before applying: take a snapshot/backup or export, verify a restore works, and confirm "
                "nothing still reads from this resource. Consider `lifecycle { prevent_destroy = true }` "
                "on resources that must never be deleted by a plan.")
    if tier == "outage":
        return ("Confirm dependent systems (DNS, clients, pipelines) can tolerate the removal or the "
                "identifier change, and schedule the apply in a maintenance window if not.")
    if tier == "trivial":
        return "Low impact; confirm it is intentional."
    return "Confirm the removal is intentional and nothing depends on this resource."


def _replace_fix(ch: Change, tier: str, paths: list[str]) -> str:
    if tier == "versioned":
        return ("Expected for this resource type: each change publishes a new version/revision. Confirm the "
                "consumers (services, rotations, launch configs) pick up the new one, then apply.")
    if tier == "trivial":
        return "Low impact; confirm the change is intentional."
    attr_hint = ", ".join(f"`{p}`" for p in paths) if paths else "the forcing attribute"
    ignore = ", ".join(paths) if paths else "<attribute>"
    fix = (f"Decide whether the change to {attr_hint} is worth recreating the resource. Options: "
           f"revert the attribute; keep the live value with `lifecycle {{ ignore_changes = [{ignore}] }}` "
           f"if it drifted outside Terraform; or if the change is required, migrate data first "
           f"(snapshot/restore, or blue-green).")
    if tier == "outage":
        fix += (" `lifecycle { create_before_destroy = true }` shortens the outage when the resource's "
                "name/identifier can coexist twice; with a fixed name the create will collide.")
    if ch.action_reason == "replace_because_tainted":
        fix = (f"The resource is tainted. If it is healthy, run `terraform untaint {ch.address}` "
               f"instead of recreating it.")
    if ch.action_reason == "replace_by_request":
        fix = "Replacement was explicitly requested with `-replace`; confirm this address is the intended one."
    if tier == "data":
        fix += " Take a verified backup before applying regardless."
        if ch.type in ("aws_db_instance", "aws_rds_cluster") and any(p.startswith("master_username") for p in paths):
            fix += (" Note: restoring from a snapshot keeps the snapshot's master username, so a different "
                    "admin login is better created in SQL than by replacing the instance.")
    return fix


def _short_addr(address: str) -> str:
    return address


def _hcl_path(rp: list) -> str:
    """Render a replace_paths entry (["vpc_config", 0, "subnet_ids"]) as vpc_config[0].subnet_ids."""
    out = ""
    for step in rp:
        if isinstance(step, int) or (isinstance(step, str) and step.isdigit()):
            out += f"[{step}]"
        else:
            out += ("." if out else "") + str(step)
    return out or "<attribute>"


# --------------------------------------------------------------------------- #
# Rule: safety mechanisms weakened                                             #
# --------------------------------------------------------------------------- #
def rule_safety(ch: Change) -> list[Finding]:
    out: list[Finding] = []
    if ch.mode != "managed" or ch.kind not in ("update", "create", "replace"):
        return out
    b = ch.before if isinstance(ch.before, dict) else {}
    a = ch.after if isinstance(ch.after, dict) else {}
    tier = classify_type(ch.type)

    for attr, safe, label, sev, fix in PROTECTION_FLAGS:
        if label is None:
            continue
        if attr not in a and attr not in b:
            continue
        av = a.get(attr)
        bv = b.get(attr)
        if ch.is_unknown(attr):
            continue
        if ch.is_sensitive(attr) or ch.is_sensitive(attr, "before"):
            av_s, bv_s = "«sensitive»", "«sensitive»"
        else:
            av_s, bv_s = hcl(av), hcl(bv)
        weakened = (bv == safe and av is not None and av != safe)
        created_unsafe = (ch.kind == "create" and av is not None and av != safe
                          and attr in ("deletion_protection", "skip_final_snapshot",
                                       "block_public_acls", "block_public_policy",
                                       "ignore_public_acls", "restrict_public_buckets",
                                       "storage_encrypted", "encrypted",
                                       "purge_protection_enabled", "https_traffic_only_enabled",
                                       "enable_https_traffic_only"))
        if weakened:
            out.append(Finding("WB-S001", sev, "safety", ch.address, ch.type, ch.kind,
                               f"{label} turned off on {ch.type}",
                               f"`{ch.address}`: `{attr}` changes from `{bv_s}` to `{av_s}`, removing {label}.",
                               fix, {"attribute": attr, "before": bv_s, "after": av_s}))
        elif created_unsafe:
            csev = "MEDIUM" if tier in ("data", "outage") else "LOW"
            if attr in ("block_public_acls", "block_public_policy", "ignore_public_acls",
                        "restrict_public_buckets"):
                csev = "HIGH"
            out.append(Finding("WB-S002", csev, "safety", ch.address, ch.type, ch.kind,
                               f"Created without {label}",
                               f"`{ch.address}` is created with `{attr} = {av_s}`.",
                               fix, {"attribute": attr, "after": av_s}))

    # Security controls switched off (type-specific attribute names)
    for type_suffix, attr, safe, sev, label in CONTROL_TOGGLES:
        if not attr or not ch.type.endswith(type_suffix):
            continue
        bv, av = b.get(attr), a.get(attr)
        if ch.is_unknown(attr) or av is None:
            continue
        if ch.kind != "create" and bv == safe and av != safe:
            out.append(Finding("WB-S010", sev, "safety", ch.address, ch.type, ch.kind,
                               f"{label} disabled",
                               f"`{ch.address}`: `{attr}` changes from `{hcl(bv)}` to `{hcl(av)}`.",
                               f"Keep {label} enabled; disabling it removes detection or protection.",
                               {"attribute": attr, "before": bv, "after": av}))
        elif ch.kind == "create" and av != safe and sev in ("HIGH", "CRITICAL"):
            out.append(Finding("WB-S010", "MEDIUM", "safety", ch.address, ch.type, ch.kind,
                               f"{label} created disabled",
                               f"`{ch.address}` is created with `{attr} = {hcl(av)}`.",
                               f"Create {label} enabled unless there is a documented reason not to.",
                               {"attribute": attr, "after": av}))

    # Secrets: immediate deletion window; log retention slashed
    if ch.type == "aws_secretsmanager_secret":
        bv, av = b.get("recovery_window_in_days"), a.get("recovery_window_in_days")
        if isinstance(av, int) and not isinstance(av, bool) and av == 0 and bv != 0:
            out.append(Finding("WB-S011", "MEDIUM", "safety", ch.address, ch.type, ch.kind,
                               "Secret recovery window set to 0",
                               f"`{ch.address}`: `recovery_window_in_days` becomes 0; a later delete is immediate and unrecoverable.",
                               "Keep a recovery window (7-30 days) for secrets that anything depends on.",
                               {"before": bv, "after": av}))
    if ch.type in ("aws_cloudwatch_log_group", "google_logging_project_bucket_config"):
        key = "retention_in_days" if ch.type == "aws_cloudwatch_log_group" else "retention_days"
        bv, av = b.get(key), a.get(key)
        if all(isinstance(x, int) and not isinstance(x, bool) for x in (bv, av)) and bv and (av < bv) and (av == 0 or av < 7):
            out.append(Finding("WB-S012", "LOW", "safety", ch.address, ch.type, ch.kind,
                               "Log retention shortened",
                               f"`{ch.address}`: `{key}` drops from {bv} to {av} days; older logs are deleted at apply.",
                               "Confirm audit/compliance retention requirements before shortening.", {"before": bv, "after": av}))

    # Database major version upgrade applied immediately
    if ch.type in ("aws_db_instance", "aws_rds_cluster") and ch.kind == "update":
        bv, av = str(b.get("engine_version") or ""), str(a.get("engine_version") or "")
        if bv and av and bv.split(".")[0] != av.split(".")[0] and not ch.is_unknown("engine_version"):
            immediate = a.get("apply_immediately") is True
            out.append(Finding("WB-S013", "MEDIUM" if immediate else "LOW", "safety", ch.address, ch.type, ch.kind,
                               f"Major engine upgrade {bv} -> {av}" + (" applied immediately" if immediate else ""),
                               f"`{ch.address}`: a major version upgrade is irreversible and restarts the database"
                               + (" as soon as the apply runs (`apply_immediately = true`)." if immediate else " in the next maintenance window."),
                               "Test the upgrade on a snapshot restore first; take a manual snapshot before applying.",
                               {"before": bv, "after": av}))

    # Service scaled to zero
    if ch.type in ("aws_ecs_service", "google_cloud_run_v2_service", "kubernetes_deployment", "kubernetes_deployment_v1") and ch.kind == "update":
        key = "desired_count" if ch.type == "aws_ecs_service" else None
        if key:
            bv, av = b.get(key), a.get(key)
            if isinstance(bv, int) and isinstance(av, int) and not isinstance(av, bool) and bv > 0 and av == 0:
                out.append(Finding("WB-S014", "MEDIUM", "safety", ch.address, ch.type, ch.kind,
                                   "Service scaled to zero",
                                   f"`{ch.address}`: `{key}` goes from {bv} to 0; the service stops serving.",
                                   "Confirm this is intended (maintenance/decommission).", {"before": bv, "after": av}))

    # Collapse the four S3 public-access-block flags into one finding
    if ch.type == "aws_s3_bucket_public_access_block":
        flags = [f for f in out if f.rule in ("WB-S001", "WB-S002")]
        if len(flags) >= 2:
            for f in flags:
                out.remove(f)
            attrs = ", ".join(f"`{f.evidence.get('attribute')}`" for f in flags)
            out.append(Finding("WB-S001", "HIGH", "safety", ch.address, ch.type, ch.kind,
                               f"S3 public access block disabled ({len(flags)} settings)",
                               f"`{ch.address}`: {attrs} are turned off, so bucket policies and ACLs can "
                               f"make objects public.",
                               "Keep all four settings `true` unless this bucket is deliberately public, and "
                               "prefer the account-level block plus CloudFront for public content.",
                               {"attributes": [f.evidence.get("attribute") for f in flags]}))

    # Backup retention reduced
    if "backup_retention_period" in a and all(isinstance(x, int) and not isinstance(x, bool)
                                                   for x in (b.get("backup_retention_period"), a.get("backup_retention_period"))):
        bv, av = b["backup_retention_period"], a["backup_retention_period"]
        if av < bv:
            sev = "HIGH" if av == 0 else "MEDIUM"
            out.append(Finding("WB-S003", sev, "safety", ch.address, ch.type, ch.kind,
                               "Backup retention reduced",
                               f"`{ch.address}`: `backup_retention_period` drops from {bv} to {av} days"
                               + (" — automated backups are disabled entirely." if av == 0 else "."),
                               "Keep retention at or above your recovery-point objective (7+ days for "
                               "production is typical).", {"before": bv, "after": av}))

    # Point-in-time recovery disabled (DynamoDB etc.)
    for key in PIT_RECOVERY_KEYS:
        bv, av = b.get(key), a.get(key)
        if _pitr_enabled(bv) and not _pitr_enabled(av) and av is not None:
            out.append(Finding("WB-S004", "MEDIUM", "safety", ch.address, ch.type, ch.kind,
                               "Point-in-time recovery disabled",
                               f"`{ch.address}`: point-in-time recovery is being turned off.",
                               "Keep PITR enabled on tables you cannot rebuild from source data.",
                               {"before": bv, "after": av}))

    # Versioning suspended
    if ch.type in ("aws_s3_bucket_versioning",):
        bs = _versioning_status(b)
        as_ = _versioning_status(a)
        if bs == "Enabled" and as_ and as_ != "Enabled":
            out.append(Finding("WB-S005", "MEDIUM", "safety", ch.address, ch.type, ch.kind,
                               "S3 versioning suspended",
                               f"`{ch.address}`: versioning goes from Enabled to {as_}; overwrites and "
                               f"deletes will no longer be recoverable.",
                               "Keep versioning enabled and use lifecycle rules to control cost.",
                               {"before": bs, "after": as_}))
    if ch.type == "aws_s3_bucket" and isinstance(b.get("versioning"), list) and b["versioning"] \
            and isinstance(a.get("versioning"), list) and a["versioning"]:
        if b["versioning"][0].get("enabled") is True and a["versioning"][0].get("enabled") is False:
            out.append(Finding("WB-S005", "MEDIUM", "safety", ch.address, ch.type, ch.kind,
                               "S3 versioning suspended",
                               f"`{ch.address}`: versioning is being disabled.",
                               "Keep versioning enabled.", {}))

    # KMS deletion window shortened
    if ch.type in ("aws_kms_key", "aws_kms_external_key"):
        bv, av = b.get("deletion_window_in_days"), a.get("deletion_window_in_days")
        if isinstance(bv, int) and isinstance(av, int) and av < bv:
            out.append(Finding("WB-S006", "MEDIUM", "safety", ch.address, ch.type, ch.kind,
                               "KMS deletion window shortened",
                               f"`{ch.address}`: `deletion_window_in_days` drops from {bv} to {av}. "
                               f"A scheduled key deletion becomes irreversible sooner.",
                               "Keep the window at 30 days for keys protecting durable data.",
                               {"before": bv, "after": av}))
        if b.get("is_enabled") is True and a.get("is_enabled") is False:
            out.append(Finding("WB-S007", "HIGH", "safety", ch.address, ch.type, ch.kind,
                               "KMS key disabled",
                               f"`{ch.address}` is being disabled; everything encrypted with it becomes "
                               f"unreadable until re-enabled.",
                               "Confirm no live data depends on this key before disabling.", {}))

    # Permissions boundary removed
    if "permissions_boundary" in a and b.get("permissions_boundary") and not a.get("permissions_boundary") \
            and not ch.is_unknown("permissions_boundary"):
        out.append(Finding("WB-S008", "HIGH", "safety", ch.address, ch.type, ch.kind,
                           "Permissions boundary removed",
                           f"`{ch.address}`: the permissions boundary `{masked(ch, 'permissions_boundary', 'before')}` "
                           f"is removed, lifting the ceiling on what this principal can be granted.",
                           "Keep the boundary unless the principal is being retired.", {}))

    # TLS minimum lowered
    for key in ("min_tls_version", "minimum_tls_version", "ssl_policy", "tls_policy"):
        bv, av = b.get(key), a.get(key)
        if isinstance(bv, str) and isinstance(av, str) and bv != av and _tls_lower(bv, av):
            out.append(Finding("WB-S009", "MEDIUM", "safety", ch.address, ch.type, ch.kind,
                               "Minimum TLS version lowered",
                               f"`{ch.address}`: `{key}` changes from `{bv}` to `{av}`.",
                               "Keep TLS 1.2 or higher.", {"before": bv, "after": av}))
    return out


def _pitr_enabled(v: Any) -> bool:
    if isinstance(v, list) and v:
        v = v[0]
    if isinstance(v, dict):
        return bool(v.get("enabled"))
    return bool(v) if isinstance(v, bool) else False


def _versioning_status(d: dict) -> str | None:
    vc = d.get("versioning_configuration")
    if isinstance(vc, list) and vc and isinstance(vc[0], dict):
        return vc[0].get("status")
    return None


def _tls_lower(before: str, after: str) -> bool:
    def score(s: str) -> float:
        m = re.search(r"1[._]?([0-3])", s)
        return float(m.group(1)) if m else -1.0
    return score(after) < score(before)


# --------------------------------------------------------------------------- #
# Rule: network exposure                                                        #
# --------------------------------------------------------------------------- #
def _as_list(v: Any) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _is_open(cidr: Any) -> bool:
    return isinstance(cidr, str) and cidr.strip().lower() in OPEN_CIDRS


def _port_range(from_port: Any, to_port: Any, protocol: Any) -> tuple[int, int, bool]:
    """Return (lo, hi, all_traffic)."""
    proto = str(protocol).lower() if protocol is not None else "tcp"
    if proto in ("-1", "all", "*", "any"):
        return 0, 65535, True
    try:
        lo = int(from_port) if from_port is not None else 0
        hi = int(to_port) if to_port is not None else lo
    except (TypeError, ValueError):
        return 0, 65535, True
    if lo == 0 and hi == 0 and proto in ("tcp", "udp", "6", "17"):
        return 0, 65535, True
    if lo == 0 and hi == 65535:
        return 0, 65535, True
    return lo, hi, False


def _parse_ports(spec: Any) -> list[tuple[int, int]]:
    """GCP/Azure style port specs: '22', '80-90', '*', ['22','443']."""
    out = []
    for s in _as_list(spec):
        s = str(s).strip()
        if s in ("*", "", "all", "any"):
            return [(0, 65535)]
        m = re.match(r"^(\d+)\s*-\s*(\d+)$", s)
        if m:
            out.append((int(m.group(1)), int(m.group(2))))
        elif s.isdigit():
            out.append((int(s), int(s)))
    return out


def _exposure_severity(lo: int, hi: int, all_traffic: bool, proto: str = "tcp") -> tuple[str, str]:
    if proto in ("icmp", "icmpv6", "1", "58"):
        return "LOW", "ICMP only (ping/traceroute); harmless by itself, but confirm it is intended"
    if all_traffic or (lo == 0 and hi == 65535):
        return "CRITICAL", "all ports/protocols"
    hits = [f"{p} ({n})" for p, n in ADMIN_PORTS.items() if lo <= p <= hi]
    if hits:
        return "CRITICAL", "admin/database port(s) " + ", ".join(hits[:4]) + ("…" if len(hits) > 4 else "")
    ports = set(range(lo, hi + 1)) if hi - lo < 2000 else set()
    if ports and ports <= WEB_PORTS:
        return "LOW", "public web port(s) only; normal for an internet-facing endpoint, confirm that is the intent"
    if ports and ports <= (WEB_PORTS | ALT_WEB_PORTS):
        return "HIGH", "alternate web port(s); fine behind a load balancer, risky on an instance"
    if hi - lo >= 100:
        return "HIGH", f"a wide range ({lo}-{hi})"
    return "HIGH", f"port(s) {lo}" + (f"-{hi}" if hi != lo else "")


def _proto(v: Any) -> str:
    p = str(v).lower() if v is not None else "tcp"
    return {"-1": "all", "6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}.get(p, p)


def _open_rules_aws_sg(obj: dict | None) -> set[tuple]:
    rules: set[tuple] = set()
    if not isinstance(obj, dict):
        return rules
    for blk in _as_list(obj.get("ingress")):
        if not isinstance(blk, dict):
            continue
        cidrs = [c for c in _as_list(blk.get("cidr_blocks")) + _as_list(blk.get("ipv6_cidr_blocks")) if _is_open(c)]
        if cidrs:
            lo, hi, all_t = _port_range(blk.get("from_port"), blk.get("to_port"), blk.get("protocol"))
            rules.add((lo, hi, all_t, tuple(sorted(cidrs)), _proto(blk.get("protocol"))))
    return rules


def _open_rules_aws_sg_rule(obj: dict | None) -> set[tuple]:
    rules: set[tuple] = set()
    if not isinstance(obj, dict):
        return rules
    if obj.get("type", "ingress") != "ingress":
        return rules
    cidrs = [c for c in _as_list(obj.get("cidr_blocks")) + _as_list(obj.get("ipv6_cidr_blocks")) if _is_open(c)]
    if cidrs:
        lo, hi, all_t = _port_range(obj.get("from_port"), obj.get("to_port"), obj.get("protocol"))
        rules.add((lo, hi, all_t, tuple(sorted(cidrs)), _proto(obj.get("protocol"))))
    return rules


def _open_rules_aws_vpc_ingress(obj: dict | None) -> set[tuple]:
    rules: set[tuple] = set()
    if not isinstance(obj, dict):
        return rules
    cidrs = [c for c in (obj.get("cidr_ipv4"), obj.get("cidr_ipv6")) if _is_open(c)]
    if cidrs:
        lo, hi, all_t = _port_range(obj.get("from_port"), obj.get("to_port"), obj.get("ip_protocol"))
        rules.add((lo, hi, all_t, tuple(sorted(cidrs)), _proto(obj.get("ip_protocol"))))
    return rules


def _open_rules_gcp_firewall(obj: dict | None) -> set[tuple]:
    rules: set[tuple] = set()
    if not isinstance(obj, dict):
        return rules
    if str(obj.get("direction", "INGRESS")).upper() != "INGRESS":
        return rules
    if obj.get("disabled") is True:
        return rules
    cidrs = [c for c in _as_list(obj.get("source_ranges")) if _is_open(c)]
    if not cidrs:
        return rules
    allows = _as_list(obj.get("allow"))
    if not allows:
        return rules
    for al in allows:
        if not isinstance(al, dict):
            continue
        proto = str(al.get("protocol", "tcp")).lower()
        if proto in ("icmp", "icmpv6", "1", "58"):
            rules.add((0, 0, False, tuple(sorted(cidrs)), proto))
            continue
        ports = _parse_ports(al.get("ports")) or [(0, 65535)]
        for lo, hi in ports:
            all_t = proto in ("all", "-1") or (lo == 0 and hi == 65535)
            rules.add((lo, hi, all_t, tuple(sorted(cidrs)), proto))
    return rules


def _open_rules_azure_nsg_rule(obj: dict | None) -> set[tuple]:
    rules: set[tuple] = set()
    if not isinstance(obj, dict):
        return rules
    if str(obj.get("direction", "Inbound")).lower() != "inbound":
        return rules
    if str(obj.get("access", "Allow")).lower() != "allow":
        return rules
    srcs = _as_list(obj.get("source_address_prefix")) + _as_list(obj.get("source_address_prefixes"))
    cidrs = [s for s in srcs if _is_open(s)]
    if not cidrs:
        return rules
    ports = _parse_ports(obj.get("destination_port_range")) + _parse_ports(obj.get("destination_port_ranges"))
    ports = ports or [(0, 65535)]
    proto = str(obj.get("protocol", "Tcp")).lower()
    for lo, hi in ports:
        all_t = (lo == 0 and hi == 65535)   # protocol "*" with one port is still just that port
        rules.add((lo, hi, all_t, tuple(sorted(cidrs)), "any" if proto == "*" else proto))
    return rules


def _open_rules_azure_nsg(obj: dict | None) -> set[tuple]:
    rules: set[tuple] = set()
    if not isinstance(obj, dict):
        return rules
    for r in _as_list(obj.get("security_rule")):
        rules |= _open_rules_azure_nsg_rule(r)
    return rules


NETWORK_EXTRACTORS = {
    "aws_security_group": _open_rules_aws_sg,
    "aws_default_security_group": _open_rules_aws_sg,
    "aws_security_group_rule": _open_rules_aws_sg_rule,
    "aws_vpc_security_group_ingress_rule": _open_rules_aws_vpc_ingress,
    "google_compute_firewall": _open_rules_gcp_firewall,
    "azurerm_network_security_rule": _open_rules_azure_nsg_rule,
    "azurerm_network_security_group": _open_rules_azure_nsg,
}

PUBLIC_TOGGLES = [
    # (types, attribute, unsafe value(s), severity, label)
    (("aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster", "aws_docdb_cluster_instance",
      "aws_neptune_cluster_instance", "aws_rds_cluster"), "publicly_accessible", (True,), "CRITICAL",
     "database reachable from the internet"),
    (("aws_instance", "aws_launch_template", "aws_launch_configuration"), "associate_public_ip_address",
     (True,), "LOW", "public IP on an instance"),
    (("aws_lambda_function_url",), "authorization_type", ("NONE",), "HIGH",
     "Lambda function URL callable without authentication"),
    (("aws_s3_bucket_acl", "aws_s3_bucket"), "acl", ("public-read", "public-read-write", "authenticated-read"),
     "CRITICAL", "public bucket ACL"),
    (("aws_lb", "aws_alb", "aws_elb"), "internal", (False,), "MEDIUM", "internet-facing load balancer"),
    (("azurerm_storage_account",), "allow_nested_items_to_be_public", (True,), "HIGH",
     "storage account allows public blobs"),
    (("azurerm_storage_account",), "allow_blob_public_access", (True,), "HIGH",
     "storage account allows public blobs"),
    (("azurerm_storage_account", "azurerm_mssql_server", "azurerm_postgresql_flexible_server",
      "azurerm_key_vault", "azurerm_container_registry", "azurerm_cosmosdb_account"),
     "public_network_access_enabled", (True,), "MEDIUM", "public network access enabled"),
    (("google_storage_bucket",), "public_access_prevention", ("inherited",), "MEDIUM",
     "public access prevention not enforced"),
    (("aws_opensearch_domain", "aws_elasticsearch_domain"), "vpc_options", None, "HIGH",
     "search domain without VPC options (internet endpoint)"),
    (("azurerm_kubernetes_cluster",), "private_cluster_enabled", (False,), "LOW", "AKS API endpoint public"),
    (("aws_ecr_repository_policy", "aws_ecr_public_repository"), None, None, "INFO", ""),
]


def rule_network(ch: Change) -> list[Finding]:
    out: list[Finding] = []
    if ch.mode != "managed" or ch.kind in ("delete", "read", "no-op", "forget"):
        return out
    b = ch.before if isinstance(ch.before, dict) else {}
    a = ch.after if isinstance(ch.after, dict) else {}

    ext = NETWORK_EXTRACTORS.get(ch.type)
    if ext:
        src_attr = {"aws_security_group": "ingress", "aws_default_security_group": "ingress",
                    "google_compute_firewall": "source_ranges", "azurerm_network_security_group": "security_rule"}.get(ch.type)
        before_rules = ext(b) if ch.kind != "create" else set()
        after_rules = ext(a)
        new_rules = after_rules - before_rules
        for lo, hi, all_t, cidrs, proto in sorted(new_rules):
            sev, what = _exposure_severity(lo, hi, all_t, proto)
            rng = "all ports" if all_t else ("ICMP" if proto in ("icmp", "icmpv6") else (f"port {lo}" if lo == hi else f"ports {lo}-{hi}"))
            if src_attr and (ch.is_sensitive(src_attr) or ch.is_sensitive(src_attr, "before")):
                detail = f"`{ch.address}` opens inbound {rng} to the internet (source details withheld: attribute marked sensitive)."
                evidence = {}
            else:
                detail = f"`{ch.address}` allows inbound {rng} from {', '.join(cidrs)} — {what}."
                evidence = {"from_port": lo, "to_port": hi, "protocol": proto, "sources": list(cidrs)}
            out.append(Finding("WB-N001", sev, "exposure", ch.address, ch.type, ch.kind,
                               f"Inbound {rng} open to the internet", detail,
                               "Restrict the source to known CIDRs, a VPN/bastion, or a security group; "
                               "for admin ports use SSM Session Manager / IAP / Bastion instead of a public "
                               "listener.", evidence))

    # Nested toggles that the flat PUBLIC_TOGGLES table cannot see
    if ch.type == "aws_eks_cluster":
        vc_a = _first_block(a.get("vpc_config"))
        vc_b = _first_block(b.get("vpc_config")) if ch.kind != "create" else {}
        pub_a, pub_b = vc_a.get("endpoint_public_access"), vc_b.get("endpoint_public_access")
        cidrs = [c for c in _as_list(vc_a.get("public_access_cidrs")) if _is_open(c)]
        if pub_a is True and (pub_b is not True or (cidrs and not any(_is_open(c) for c in _as_list(vc_b.get("public_access_cidrs"))))):
            sev = "HIGH" if cidrs or not vc_a.get("public_access_cidrs") else "MEDIUM"
            out.append(Finding("WB-N003", sev, "exposure", ch.address, ch.type, ch.kind,
                               "EKS API endpoint reachable from the internet",
                               f"`{ch.address}`: `vpc_config[0].endpoint_public_access` is true"
                               + (f" with public_access_cidrs {', '.join(cidrs)}" if cidrs else " with no CIDR restriction") + ".",
                               "Restrict `public_access_cidrs` to known ranges, or use a private endpoint only.",
                               {"public_access_cidrs": _as_list(vc_a.get("public_access_cidrs"))}))
    if ch.type == "google_compute_instance":
        def _has_external_ip(d: dict) -> bool:
            return any(isinstance(ni, dict) and _as_list(ni.get("access_config")) for ni in _as_list(d.get("network_interface")))
        if _has_external_ip(a) and (ch.kind == "create" or not _has_external_ip(b)):
            out.append(Finding("WB-N002", "LOW", "exposure", ch.address, ch.type, ch.kind,
                               "External IP on a VM",
                               f"`{ch.address}` gets an external IP (`network_interface[].access_config`).",
                               "Prefer private VMs with Cloud NAT and IAP TCP forwarding.", {}))
    if ch.type == "github_repository":
        became_public = (a.get("visibility") == "public" and (ch.kind == "create" or b.get("visibility") != "public")) or \
                        (a.get("private") is False and (ch.kind == "create" or b.get("private") is not False))
        if became_public and not ch.is_unknown("visibility"):
            out.append(Finding("WB-N007", "HIGH", "exposure", ch.address, ch.type, ch.kind,
                               "Repository becomes public",
                               f"`{ch.address}` will be publicly visible (code, history, and issues).",
                               "Confirm no secrets or private history are in the repository before making it public.", {}))

    # Public toggles
    for types, attr, unsafe, sev, label in PUBLIC_TOGGLES:
        if ch.type not in types or not attr:
            continue
        av = a.get(attr)
        bv = b.get(attr)
        if ch.is_unknown(attr):
            continue
        if unsafe is None:
            # presence-based (access_config present => external IP; vpc_options absent => public)
            if attr == "vpc_options":
                if ch.kind == "create" and not av:
                    out.append(Finding("WB-N002", sev, "exposure", ch.address, ch.type, ch.kind,
                                       label.capitalize(), f"`{ch.address}` is created without `{attr}`.",
                                       "Deploy inside a VPC and use fine-grained access control.", {}))
                continue
            became = bool(av) and not bool(bv) if ch.kind != "create" else bool(av)
            if became:
                out.append(Finding("WB-N002", sev, "exposure", ch.address, ch.type, ch.kind,
                                   label.capitalize(), f"`{ch.address}` gains `{attr}`.",
                                   "Confirm a public address is needed; prefer NAT/IAP/bastion.", {}))
            continue
        became_unsafe = av in unsafe and (ch.kind == "create" or bv not in unsafe)
        if became_unsafe:
            fix = {
                "publicly_accessible": "Set `publicly_accessible = false` and reach the database through the VPC, a bastion, or SSM port forwarding.",
                "authorization_type": "Use `authorization_type = \"AWS_IAM\"` or put the function behind API Gateway with auth.",
                "acl": "Use `private` and grant access via bucket policy/IAM; enable the account-level public access block.",
                "internal": "If this LB must be internet-facing, make sure listeners use TLS and a WAF is attached.",
                "public_network_access_enabled": "Use private endpoints and disable public network access.",
                "allow_nested_items_to_be_public": "Set to false unless the container must serve public content.",
                "allow_blob_public_access": "Set to false unless the container must serve public content.",
                "endpoint_public_access": "Restrict with `public_access_cidrs` or use a private endpoint.",
                "private_cluster_enabled": "Consider a private cluster or authorized IP ranges.",
                "public_access_prevention": "Set `public_access_prevention = \"enforced\"`.",
                "associate_public_ip_address": "Prefer private subnets with NAT; use SSM/IAP for access.",
            }.get(attr, "Confirm this exposure is intended.")
            out.append(Finding("WB-N003", sev, "exposure", ch.address, ch.type, ch.kind,
                               label.capitalize(),
                               f"`{ch.address}`: `{attr}` is `{hcl(av)}`" + (f" (was `{hcl(bv)}`)" if ch.kind != "create" else "") + ".",
                               fix, {"attribute": attr, "before": bv, "after": av}))

    # Cloud SQL: public IP + authorized network 0.0.0.0/0
    if ch.type == "google_sql_database_instance":
        after_nets = _gcp_sql_open_networks(a)
        before_nets = _gcp_sql_open_networks(b) if ch.kind != "create" else set()
        if after_nets - before_nets:
            out.append(Finding("WB-N004", "CRITICAL", "exposure", ch.address, ch.type, ch.kind,
                               "Cloud SQL instance reachable from the whole internet",
                               f"`{ch.address}` has a public IPv4 address and an authorized network of "
                               f"{', '.join(sorted(after_nets - before_nets))}: any host can attempt to connect.",
                               "Remove the 0.0.0.0/0 authorized network; use private IP, the Cloud SQL Auth "
                               "Proxy, or specific CIDRs.", {"authorized_networks": sorted(after_nets)}))
        elif _gcp_sql_public_ip(a) and not _gcp_sql_public_ip(b):
            out.append(Finding("WB-N005", "LOW", "exposure", ch.address, ch.type, ch.kind,
                               "Cloud SQL public IP enabled",
                               f"`{ch.address}` gets a public IPv4 address (no open authorized networks yet).",
                               "Prefer private IP unless external access is required.", {}))

    # Azure database firewall rules covering the internet
    if ch.type in ("azurerm_postgresql_flexible_server_firewall_rule", "azurerm_mysql_flexible_server_firewall_rule",
                   "azurerm_mssql_firewall_rule", "azurerm_postgresql_firewall_rule", "azurerm_mysql_firewall_rule",
                   "azurerm_mariadb_firewall_rule", "azurerm_sql_firewall_rule", "azurerm_redis_firewall_rule"):
        start, end = str(a.get("start_ip_address") or a.get("start_ip") or ""), str(a.get("end_ip_address") or a.get("end_ip") or "")
        was = (str(b.get("start_ip_address") or b.get("start_ip") or ""), str(b.get("end_ip_address") or b.get("end_ip") or ""))
        if start == "0.0.0.0" and end in ("255.255.255.255", "0.0.0.0") and (ch.kind == "create" or was != (start, end)):
            label = ("Azure-services-only rule (0.0.0.0-0.0.0.0): any Azure tenant's resources can connect"
                     if end == "0.0.0.0" else "the entire IPv4 internet can connect")
            out.append(Finding("WB-N006", "CRITICAL" if end != "0.0.0.0" else "HIGH", "exposure", ch.address,
                               ch.type, ch.kind, "Database firewall opened to the internet",
                               f"`{ch.address}` allows {start}–{end}: {label}.",
                               "Restrict to specific client ranges or use private endpoints / VNet rules.",
                               {"start": start, "end": end}))
    return out


def _first_block(v: Any) -> dict:
    v = _as_list(v)
    return v[0] if v and isinstance(v[0], dict) else {}


def _gcp_sql_ip_config(d: dict) -> dict:
    settings = _as_list(d.get("settings"))
    if settings and isinstance(settings[0], dict):
        ipc = _as_list(settings[0].get("ip_configuration"))
        if ipc and isinstance(ipc[0], dict):
            return ipc[0]
    return {}


def _gcp_sql_public_ip(d: dict) -> bool:
    return bool(_gcp_sql_ip_config(d).get("ipv4_enabled"))


def _gcp_sql_open_networks(d: dict) -> set[str]:
    ipc = _gcp_sql_ip_config(d)
    if not ipc.get("ipv4_enabled"):
        return set()
    nets = set()
    for n in _as_list(ipc.get("authorized_networks")):
        if isinstance(n, dict) and _is_open(n.get("value")):
            nets.add(str(n.get("value")))
    return nets


# --------------------------------------------------------------------------- #
# Rule: IAM / privilege widening                                                #
# --------------------------------------------------------------------------- #
POLICY_ATTRS = ("policy", "assume_role_policy", "inline_policy", "key_policy", "repository_policy",
                "resource_policy", "access_policies", "policy_document", "secret_policy",
                "bucket_policy", "trust_policy")
TRUST_TYPES = ("aws_iam_role",)
RESOURCE_POLICY_TYPES = ("aws_s3_bucket_policy", "aws_sqs_queue_policy", "aws_sns_topic_policy",
                         "aws_kms_key", "aws_ecr_repository_policy", "aws_secretsmanager_secret_policy",
                         "aws_lambda_permission", "aws_opensearch_domain_policy",
                         "aws_elasticsearch_domain_policy", "aws_efs_file_system_policy",
                         "aws_backup_vault_policy", "aws_glacier_vault", "aws_api_gateway_rest_api_policy",
                         "aws_iot_policy", "aws_cloudwatch_log_resource_policy", "aws_s3_bucket",
                         "aws_sqs_queue", "aws_sns_topic", "aws_ecr_repository", "aws_secretsmanager_secret",
                         "aws_vpc_endpoint", "aws_codeartifact_domain_permissions_policy",
                         "aws_lambda_layer_version_permission", "aws_ses_identity_policy",
                         "aws_eventbridge_bus_policy", "aws_cloudwatch_event_bus_policy",
                         "aws_efs_access_point", "aws_media_store_container_policy")


def _parse_policy(v: Any) -> dict | None:
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s.startswith("{"):
            try:
                return json.loads(s)
            except json.JSONDecodeError:
                return None
    return None


def _statements(doc: dict | None) -> list[dict]:
    if not isinstance(doc, dict):
        return []
    st = doc.get("Statement")
    if isinstance(st, dict):
        return [st]
    if isinstance(st, list):
        return [s for s in st if isinstance(s, dict)]
    return []


def _lower_list(v: Any) -> list[str]:
    return [str(x).lower() for x in _as_list(v)]


def _principal_wildcard(p: Any) -> bool:
    if p == "*":
        return True
    if isinstance(p, dict):
        for k, v in p.items():
            if k.lower() in ("aws", "*") and ("*" in _as_list(v)):
                return True
    return False


def _principal_accounts(p: Any) -> list[str]:
    accts = []
    if isinstance(p, dict):
        for v in _as_list(p.get("AWS")):
            m = re.match(r"^arn:aws[a-z-]*:iam::(\d{12}):", str(v))
            if m:
                accts.append(m.group(1))
            elif re.fullmatch(r"\d{12}", str(v)):
                accts.append(str(v))
    return accts


SOURCE_SCOPING_CONDITION_KEYS = ("aws:sourcearn", "aws:sourceaccount", "aws:sourceowner", "aws:principalorgid",
                                 "aws:principalaccount", "aws:sourcevpce", "aws:sourcevpc", "aws:principalarn",
                                 "aws:sourceip", "aws:vpcsourceip", "aws:principalorgpaths", "aws:resourceorgid")


def _condition_keys(st: dict) -> set[str]:
    keys: set[str] = set()
    cond = st.get("Condition")
    if isinstance(cond, dict):
        for op in cond.values():
            if isinstance(op, dict):
                keys.update(str(k).lower() for k in op.keys())
    return keys


def _only_local_root_principal(principal: Any) -> bool:
    """True when the statement's only principal is this account's root (the 'enable IAM' pattern)."""
    if not isinstance(principal, dict) or set(k.lower() for k in principal) != {"aws"}:
        return False
    accts = _principal_accounts(principal)
    vals = _as_list(principal.get("AWS"))
    if not accts or len(accts) != len(vals):
        return False
    return _LOCAL_ACCOUNT is not None and all(a == _LOCAL_ACCOUNT for a in accts) and \
        all(str(v).endswith(":root") or re.fullmatch(r"\d{12}", str(v)) for v in vals)


def _risky_signatures(doc: dict | None, is_trust: bool, is_resource_policy: bool) -> list[tuple[str, str, str, str]]:
    """Return (severity, key, title, detail) for each risky Allow statement."""
    out = []
    for st in _statements(doc):
        if str(st.get("Effect", "Allow")).lower() != "allow":
            continue
        has_cond = bool(st.get("Condition"))
        cond_keys = _condition_keys(st)
        source_scoped = any(k in SOURCE_SCOPING_CONDITION_KEYS for k in cond_keys)
        actions = _lower_list(st.get("Action"))
        shown_actions = [str(x) for x in _as_list(st.get("Action"))]
        not_actions = _lower_list(st.get("NotAction"))
        resources = _lower_list(st.get("Resource"))
        not_resources = st.get("NotResource")
        principal = st.get("Principal")
        not_principal = st.get("NotPrincipal")
        sid = st.get("Sid", "")
        res_all = ("*" in resources) or (not resources and not_resources is None and not is_trust) \
            or (not_resources is not None)
        label = f"Statement {sid or '(no Sid)'}"

        if is_trust or (is_resource_policy and (principal is not None or not_principal is not None)):
            if not_principal is not None and principal is None:
                out.append(("HIGH", f"notprincipal:{sid}", "Allow with NotPrincipal (everyone except the listed)",
                            f"{label} allows {', '.join(shown_actions[:4]) or 'actions'} to every principal except the listed ones; "
                            f"this is effectively public."))
            if _principal_wildcard(principal):
                if source_scoped:
                    out.append(("LOW", f"principal:*:scoped:{sid}",
                                "Principal * scoped by a source condition",
                                f"{label} allows {', '.join(shown_actions[:6]) or 'actions'} to any principal, limited by "
                                f"{', '.join(sorted(k for k in cond_keys if k in SOURCE_SCOPING_CONDITION_KEYS))}. "
                                f"This is the normal service-to-service pattern (e.g. SNS -> SQS); verify the ARN/account in the condition."))
                else:
                    sev = "HIGH" if has_cond else "CRITICAL"
                    who = "anyone (Principal *)"
                    if is_trust:
                        title = "Role can be assumed by any AWS principal"
                        detail = (f"{label} trusts {who}"
                                  + (" — a Condition narrows it; verify it" if has_cond else " with no Condition; any AWS account can assume this role") + ".")
                    else:
                        title = "Resource policy grants public access"
                        detail = (f"{label} allows {', '.join(shown_actions[:6]) or 'actions'} to {who}"
                                  + (" — a Condition narrows it; verify it" if has_cond else " with no Condition") + ".")
                    out.append((sev, f"principal:*:{sid}:{','.join(actions)}", title, detail))
            elif _only_local_root_principal(principal):
                out.append(("INFO", f"principal:localroot:{sid}", "Account-level trust (this account's root)",
                            f"{label} grants access to this account's own root principal, which delegates to IAM "
                            f"policies in the account. This is the standard pattern for key/bucket policies and same-account roles."))
                if is_trust:
                    continue
                # a same-account root statement with svc:* is the canonical KMS/S3 'enable IAM' policy
                if any(a.endswith(":*") for a in actions) and res_all:
                    continue
            else:
                for acct in _principal_accounts(principal):
                    if _LOCAL_ACCOUNT and acct == _LOCAL_ACCOUNT:
                        continue
                    out.append(("MEDIUM" if not has_cond else "LOW", f"principal:acct:{acct}:{sid}",
                                f"Trust for account {acct}" + ("" if _LOCAL_ACCOUNT else " (possibly cross-account)"),
                                f"{label} trusts account {acct}"
                                + ("" if has_cond else " with no Condition (no ExternalId / SourceArn / PrincipalOrgID)") + "."))
            if is_trust and isinstance(principal, dict) and principal.get("Federated"):
                fed = " ".join(_lower_list(principal.get("Federated")))
                cond_text = json.dumps(st.get("Condition") or {}).lower()
                if "token.actions.githubusercontent.com" in fed and ":sub" not in cond_text:
                    out.append(("HIGH", f"oidc:github:{sid}",
                                "GitHub OIDC trust without a `sub` condition",
                                "Any GitHub repository/workflow can assume this role. Add a condition on "
                                "`token.actions.githubusercontent.com:sub` (repo and branch/environment)."))
                elif not has_cond and "amazonaws.com" not in fed:
                    out.append(("HIGH", f"oidc:nocond:{sid}",
                                "Federated trust without conditions",
                                f"Trust for `{fed}` has no Condition restricting audience/subject."))
            if is_trust:
                continue

        if "*" in actions and res_all:
            out.append(("HIGH" if has_cond else "CRITICAL", f"admin:{sid}",
                        "Full administrative access (Action * on Resource *)",
                        f"{label} allows every action on every resource"
                        + (" (conditionally)" if has_cond else "") + "."))
            continue
        if "*" in actions and not res_all and not is_resource_policy:
            out.append(("MEDIUM", f"allactions:{sid}", "All actions on specific resources",
                        f"{label} allows every action (`*`) on {', '.join(resources[:3])}{'…' if len(resources) > 3 else ''}; "
                        f"that includes delete, policy, and permission changes on those resources."))
            continue
        if not_actions and not actions:
            out.append(("HIGH", f"notaction:{sid}",
                        "Allow with NotAction (inverted allow)",
                        f"{label} allows everything except {', '.join(not_actions[:5])}"
                        + ("…" if len(not_actions) > 5 else "") + "; this is usually far broader than intended."))
            continue
        svc_wild = [a for a in shown_actions if a.endswith(":*")]
        if svc_wild and res_all:
            out.append(("MEDIUM" if has_cond else "HIGH", f"svcwild:{sid}:{','.join(svc_wild)}",
                        f"Service-wide wildcard: {', '.join(svc_wild[:4])}",
                        f"{label} grants all actions for {', '.join(svc_wild[:4])} on every resource."))
        if any(a == "iam:passrole" or a == "iam:*" for a in actions) and res_all:
            out.append(("HIGH", f"passrole:{sid}", "iam:PassRole on any role",
                        f"{label} allows passing ANY role to services; combined with "
                        f"a create/update permission on a compute service this is privilege escalation to any "
                        f"role in the account (including administrators)."))
        esc = sorted(a for a in actions if a in ESCALATION_ACTIONS or
                     (a.endswith("*") and any(e.startswith(a[:-1]) for e in ESCALATION_ACTIONS if a[:-1])))
        esc = [e for e in esc if e not in ("iam:*",)]
        if esc and res_all and "*" not in actions:
            sev = "HIGH" if not has_cond else "MEDIUM"
            if esc == ["sts:assumerole"]:
                sev = "MEDIUM"
            out.append((sev, f"esc:{sid}:{','.join(esc)}",
                        f"Privilege-escalation capable action(s): {', '.join(esc[:4])}",
                        f"{label} grants {', '.join(esc[:4])} on every resource."))
        if not_resources is not None and actions and "*" not in actions:
            out.append(("MEDIUM", f"notresource:{sid}", "Allow with NotResource",
                        f"{label} allows {', '.join(shown_actions[:4])} on everything except "
                        f"the listed resources."))
    return out


def rule_iam(ch: Change) -> list[Finding]:
    out: list[Finding] = []
    if ch.mode != "managed" or ch.kind in ("read", "no-op", "forget"):
        return out
    b = ch.before if isinstance(ch.before, dict) else {}
    a = ch.after if isinstance(ch.after, dict) else {}

    if ch.kind == "delete":
        # Losing an organization policy guard is a widening; losing a policy is covered by destructive rules.
        if ch.type in ("aws_organizations_policy", "aws_organizations_policy_attachment"):
            out.append(Finding("WB-I006", "HIGH", "iam", ch.address, ch.type, "delete",
                               "Organization service control policy removed",
                               f"`{ch.address}` is removed; guardrails it enforced across accounts no longer apply.",
                               "Confirm the service control policy is superseded before removing it.", {}))
        return out

    is_trust = ch.type in TRUST_TYPES
    is_res = ch.type in RESOURCE_POLICY_TYPES
    for attr in POLICY_ATTRS:
        if attr not in a:
            continue
        if ch.is_unknown(attr):
            continue
        after_docs = _policy_docs(a.get(attr))
        before_docs = _policy_docs(b.get(attr)) if ch.kind != "create" else []
        trust_attr = attr == "assume_role_policy" or (is_trust and attr == "trust_policy")
        after_sigs = {}
        for doc in after_docs:
            for sev, key, title, detail in _risky_signatures(doc, trust_attr, is_res or attr in ("key_policy", "repository_policy", "resource_policy", "secret_policy", "bucket_policy")):
                after_sigs[key] = (sev, title, detail)
        before_keys = set()
        for doc in before_docs:
            for sev, key, title, detail in _risky_signatures(doc, trust_attr, is_res):
                before_keys.add(key)
        doc_sensitive = ch.is_sensitive(attr) or ch.is_sensitive(attr, "before")
        for key, (sev, title, detail) in after_sigs.items():
            shown = "(details withheld: the policy attribute is marked sensitive)" if doc_sensitive else detail
            if key in before_keys:
                if sev == "INFO":
                    continue
                out.append(Finding("WB-I000", "INFO", "iam", ch.address, ch.type, ch.kind,
                                   f"Pre-existing: {title}",
                                   f"`{ch.address}` `{attr}` already had this before the change: {shown}",
                                   "Not introduced by this plan, but worth fixing separately.", {}))
                continue
            fix = _iam_fix(title)
            out.append(Finding("WB-I001", sev, "iam", ch.address, ch.type, ch.kind, title,
                               f"`{ch.address}` `{attr}`: {shown}", fix, {"attribute": attr}))

    # Managed policy attachments
    arns = []
    for attr in ("policy_arn", "managed_policy_arns", "policy_arns"):
        if attr in a and not ch.is_unknown(attr):
            new = set(map(str, _as_list(a.get(attr)))) - (set(map(str, _as_list(b.get(attr)))) if ch.kind != "create" else set())
            arns.extend(sorted(new))
    for arn in arns:
        low = arn.lower()
        if any(low.endswith(s.lower()) for s in ADMIN_POLICY_SUFFIXES):
            sev, label = "CRITICAL", "administrator-level managed policy"
        elif any(m.lower() in low for m in BROAD_POLICY_MARKERS):
            sev, label = "HIGH", "broad managed policy"
        else:
            continue
        out.append(Finding("WB-I002", sev, "iam", ch.address, ch.type, ch.kind,
                           f"Attaches {label}: {arn.rsplit('/', 1)[-1]}",
                           f"`{ch.address}` attaches `{arn}`.",
                           "Replace with a customer-managed policy scoped to the actions and resources the "
                           "workload actually uses (IAM Access Analyzer can generate one from CloudTrail).",
                           {"policy_arn": arn}))

    # Long-lived credentials
    if ch.kind == "create" and ch.type in ("aws_iam_access_key", "google_service_account_key",
                                           "azuread_application_password", "azuread_service_principal_password"):
        out.append(Finding("WB-I003", "MEDIUM", "iam", ch.address, ch.type, "create",
                           "Long-lived credential created",
                           f"`{ch.address}` creates a static credential ({ch.type}); it will live in state "
                           f"and wherever it is passed.",
                           "Prefer roles / workload identity federation (OIDC) over static keys; if a key is "
                           "unavoidable, rotate it and keep it out of state outputs.", {}))
    if ch.kind == "create" and ch.type == "aws_iam_user_login_profile":
        out.append(Finding("WB-I003", "LOW", "iam", ch.address, ch.type, "create",
                           "Console login profile created",
                           f"`{ch.address}` creates console access for an IAM user.",
                           "Prefer SSO/identity center; require MFA.", {}))

    # GCP IAM
    if ch.type.startswith("google_") and "_iam_" in ch.type:
        members = set(map(str, _as_list(a.get("members")) + _as_list(a.get("member"))))
        if ch.kind != "create":
            members -= set(map(str, _as_list(b.get("members")) + _as_list(b.get("member"))))
        role = str(a.get("role") or "")
        for m in sorted(members):
            if m in ("allUsers",):
                out.append(Finding("WB-I004", "CRITICAL", "iam", ch.address, ch.type, ch.kind,
                                   f"Grants {role or 'a role'} to allUsers (public)",
                                   f"`{ch.address}` binds `{role}` to `allUsers`: anyone on the internet.",
                                   "Remove the public binding; use signed URLs or IAP for public content.", {}))
            elif m in ("allAuthenticatedUsers",):
                out.append(Finding("WB-I004", "HIGH", "iam", ch.address, ch.type, ch.kind,
                                   f"Grants {role or 'a role'} to allAuthenticatedUsers",
                                   f"`{ch.address}` binds `{role}` to `allAuthenticatedUsers`: any Google account.",
                                   "Bind specific principals or groups instead.", {}))
        if role and (ch.kind == "create" or role != str(b.get("role") or "") or members):
            sev = GCP_ADMIN_ROLES.get(role)
            if sev:
                who = ", ".join(sorted(members)[:3]) if members else "the bound principals"
                if ch.is_sensitive("members") or ch.is_sensitive("member"):
                    who = "«sensitive»"
                out.append(Finding("WB-I005", sev, "iam", ch.address, ch.type, ch.kind,
                                   f"Grants broad role {role}",
                                   f"`{ch.address}` grants `{role}` to {who}.",
                                   "Grant the narrowest predefined role that covers the needed permissions, "
                                   "scoped to the resource rather than the project where possible.", {"role": role}))
        if ch.type.endswith("_iam_policy") and ch.kind in ("create", "update"):
            out.append(Finding("WB-I007", "MEDIUM", "iam", ch.address, ch.type, ch.kind,
                               "Authoritative IAM policy (replaces all bindings)",
                               f"`{ch.address}` is authoritative: any binding not listed in it is removed "
                               f"on apply, including ones added outside Terraform.",
                               "Prefer `*_iam_member` / `*_iam_binding` unless you intend to own every binding.", {}))

    # Azure role assignments (by name or by built-in role definition id)
    if ch.type == "azurerm_role_assignment" and ch.kind in ("create", "update"):
        role = str(a.get("role_definition_name") or "").lower()
        rid = str(a.get("role_definition_id") or "").lower()
        for guid, rname in AZURE_ROLE_GUIDS.items():
            if rid.endswith(guid):
                role = role or rname
        scope = str(a.get("scope") or "")
        if ch.is_sensitive("scope"):
            scope = "«sensitive»"
        sev = AZURE_ADMIN_ROLES.get(role)
        if sev:
            broad_scope = bool(re.match(r"^/subscriptions/[^/]+/?$", scope)) or "/providers/Microsoft.Management/" in scope
            if not broad_scope and sev == "CRITICAL":
                sev = "HIGH"
            elif not broad_scope and sev == "HIGH":
                sev = "MEDIUM"
            out.append(Finding("WB-I005", sev, "iam", ch.address, ch.type, ch.kind,
                               f"Assigns {a.get('role_definition_name') or role.title()} at {'subscription/management-group' if broad_scope else 'resource'} scope",
                               f"`{ch.address}` assigns `{a.get('role_definition_name') or role.title()}` on `{_shorten(scope, 80)}`.",
                               "Assign the least-privileged built-in role at the narrowest scope; avoid Owner "
                               "and User Access Administrator outside break-glass identities.", {"scope": scope}))
    # Kubernetes: cluster-admin handed to broad groups
    if ch.type in ("kubernetes_cluster_role_binding", "kubernetes_cluster_role_binding_v1",
                   "kubernetes_role_binding", "kubernetes_role_binding_v1") and ch.kind in ("create", "update"):
        role_ref = _first_block(a.get("role_ref"))
        subjects = [x for x in _as_list(a.get("subject")) if isinstance(x, dict)]
        names = [str(x.get("name") or "") for x in subjects]
        if str(role_ref.get("name") or "") in ("cluster-admin", "admin", "edit") and names:
            broad = [n for n in names if n.startswith("system:authenticated") or n.startswith("system:unauthenticated")
                     or n == "system:serviceaccounts"]
            sev = "CRITICAL" if broad else ("HIGH" if role_ref.get("name") == "cluster-admin" else "MEDIUM")
            out.append(Finding("WB-I008", sev, "iam", ch.address, ch.type, ch.kind,
                               f"Binds {role_ref.get('name')} to {', '.join(broad or names[:3])}",
                               f"`{ch.address}` binds the `{role_ref.get('name')}` role to {', '.join(names[:4])}"
                               + (" — every authenticated/anonymous identity in the cluster." if broad else "."),
                               "Bind admin roles to specific groups or service accounts; never to system:authenticated or system:unauthenticated.",
                               {"subjects": names}))
    return out


def _policy_docs(v: Any) -> list[dict]:
    docs = []
    for item in _as_list(v):
        if isinstance(item, dict) and "policy" in item and isinstance(item.get("policy"), str):
            d = _parse_policy(item["policy"])  # aws_iam_role.inline_policy blocks
            if d:
                docs.append(d)
            continue
        d = _parse_policy(item)
        if d:
            docs.append(d)
    return docs


def _iam_fix(title: str) -> str:
    t = title.lower()
    if "administrative" in t:
        return ("Replace `\"Action\": \"*\"` / `\"Resource\": \"*\"` with the specific actions and resource ARNs "
                "the workload needs. If admin access is truly required, scope it with conditions "
                "(source IP/VPC, MFA, tags) and a permissions boundary.")
    if "assumed by any" in t:
        return ("Name the exact principals (account IDs, role ARNs) and add a Condition such as "
                "`aws:PrincipalOrgID` or `sts:ExternalId`.")
    if "public access" in t:
        return ("If the content really must be public, prefer serving it through a CDN (e.g. CloudFront with "
                "Origin Access Control) and keep the resource itself private. Otherwise restrict `Principal` "
                "to specific accounts/roles and add a Condition such as `aws:PrincipalOrgID` or `aws:SourceArn`.")
    if "cross-account" in t:
        return "Verify the account is yours/expected and add `sts:ExternalId` or `aws:PrincipalOrgID` conditions."
    if "github oidc" in t:
        return ("Add `\"StringLike\": {\"token.actions.githubusercontent.com:sub\": \"repo:ORG/REPO:ref:refs/heads/main\"}` "
                "(or the environment form) and `StringEquals` on `:aud` = `sts.amazonaws.com`.")
    if "notaction" in t or "notresource" in t:
        return "Rewrite as an explicit allow-list of actions/resources; use NotAction only in Deny statements."
    if "service-wide" in t:
        return "List the specific actions (e.g. `s3:GetObject`, `s3:PutObject`) and scope `Resource` to the ARNs used."
    if "passrole" in t:
        return ("Scope `iam:PassRole` to the specific role ARNs (or an IAM path) and add "
                "`iam:PassedToService` conditions.")
    if "escalation" in t:
        return "Remove or scope these actions to specific policy/role ARNs; they allow a principal to grow its own permissions."
    return "Scope the statement to specific actions and resources."


# --------------------------------------------------------------------------- #
# Rule: plan-level                                                              #
# --------------------------------------------------------------------------- #
def rule_plan_level(plan: dict, changes: list[Change]) -> list[Finding]:
    out: list[Finding] = []
    managed = [c for c in changes if c.mode == "managed" and c.kind != "no-op"]
    deletes = [c for c in managed if c.kind == "delete" and not c.deposed]
    n_del = len(deletes)
    heavy = [c for c in managed if c.kind in ("delete", "replace") and not c.deposed
             and classify_type(c.type) in ("data", "outage", "default")]
    n_rep = sum(1 for c in managed if c.kind == "replace")
    n_cre = sum(1 for c in managed if c.kind == "create")
    n_upd = sum(1 for c in managed if c.kind == "update")

    if plan.get("errored") is True:
        out.append(Finding("WB-P001", "CRITICAL", "plan", "(plan)", "", "",
                           "Plan errored", "The plan recorded `errored: true`; it is not applyable.",
                           "Fix the error and re-plan.", {}))
    if plan.get("complete") is False:
        out.append(Finding("WB-P002", "HIGH", "plan", "(plan)", "", "",
                           "Partial plan (-target / -exclude, or deferred changes)",
                           "`complete: false`: the plan does not cover the whole configuration, so dependent "
                           "resources are not being updated. Applying a partial plan can leave the "
                           "configuration inconsistent, and a later full plan may make surprising changes.",
                           "Use targeting only for recovery; follow up with a full `terraform plan`.", {}))
    if n_del >= 3 and n_cre == 0 and n_upd == 0 and n_rep == 0:
        serious = any(classify_type(c.type) in ("data", "outage") for c in deletes)
        out.append(Finding("WB-P003", "CRITICAL" if (serious or n_del >= 10) else "HIGH", "plan", "(plan)", "", "",
                           f"This is a destroy plan: {n_del} resources will be destroyed",
                           "Every change in this plan is a deletion. This is what `terraform destroy`, "
                           "an empty configuration, a wrong workspace, or a missing/empty state file produces.",
                           "Confirm you are in the intended workspace/backend and that destroying everything "
                           "is the goal. If the state file is missing, STOP: applying will try to recreate "
                           "resources that already exist, or destroy what the state says exists.", {}))
    elif len(heavy) >= 10:
        out.append(Finding("WB-P004", "HIGH", "plan", "(plan)", "", "",
                           f"Large blast radius: {len(heavy)} non-trivial destroys/replacements",
                           "A large number of resources are recreated or removed in one apply.",
                           "Split the change into smaller applies, or apply in a maintenance window with "
                           "a tested rollback.", {}))
    drift = plan.get("resource_drift")
    drift = [d for d in drift if isinstance(d, dict)] if isinstance(drift, list) else []
    if drift:
        addrs = [str(d.get("address", "?")) for d in drift][:8]
        vanished = [str(d.get("address", "?")) for d in drift
                    if isinstance(d.get("change"), dict) and d["change"].get("actions") == ["delete"]]
        detail = (f"{len(drift)} resource(s) changed outside Terraform since the last apply: "
                  f"{', '.join(addrs)}{'…' if len(drift) > 8 else ''}.")
        if vanished:
            detail += f" {len(vanished)} no longer exist: {', '.join(vanished[:5])}."
        out.append(Finding("WB-P005", "INFO", "plan", "(plan)", "", "", "Drift detected", detail,
                           "Review whether the manual changes should be kept (`ignore_changes` / update the "
                           "config) or reverted by this apply.", {"count": len(drift)}))
    imports = [c.address for c in changes if c.importing]
    if imports:
        out.append(Finding("WB-P006", "INFO", "plan", "(plan)", "", "",
                           f"{len(imports)} resource(s) imported into state",
                           f"Imported: {', '.join(imports[:6])}{'…' if len(imports) > 6 else ''}. Imports adopt existing "
                           f"objects; check that no other change in this plan then modifies them unexpectedly.",
                           "Compare the imported attributes with the configuration after apply.", {"imports": imports}))
    return out


# --------------------------------------------------------------------------- #
# Orchestration                                                                 #
# --------------------------------------------------------------------------- #
_LOCAL_ACCOUNT: str | None = None
_ACCT_IN_ARN = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:(\d{12}):")


def _infer_local_account(changes: list[Change]) -> str | None:
    """The account that owns this plan is the one that appears most in ARNs across all values."""
    counts: dict[str, int] = {}

    def walk(v: Any) -> None:
        if isinstance(v, str):
            for m in _ACCT_IN_ARN.finditer(v):
                counts[m.group(1)] = counts.get(m.group(1), 0) + 1
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    for c in changes:
        walk(c.before)
        walk(c.after)
    if not counts:
        return None
    return max(counts.items(), key=lambda kv: kv[1])[0]


RENAME_IGNORE_KEYS = {"id", "arn", "tags_all", "unique_id", "self_link", "etag", "fingerprint",
                      "creation_date", "created_at", "url", "uri", "hosted_zone_id", "address",
                      "endpoint", "resource_id", "owner_id", "policy_id", "version", "latest_version"}


def _pair_renames(changes: list[Change]) -> None:
    """Mark deletes that have a same-type create with matching values (a rename without a `moved` block)."""
    creates = [c for c in changes if c.mode == "managed" and c.kind == "create" and isinstance(c.after, dict)]
    used: set[str] = set()
    for d in changes:
        if d.mode != "managed" or d.kind != "delete" or not isinstance(d.before, dict):
            continue
        if d.action_reason not in ("delete_because_no_resource_config", "delete_because_no_module"):
            continue
        for c in creates:
            if c.type != d.type or c.address in used:
                continue
            comparable = 0
            mismatch = False
            for k, bv in d.before.items():
                if k in RENAME_IGNORE_KEYS or bv in (None, "", [], {}):
                    continue
                if c.is_unknown(k) or k not in c.after or c.after.get(k) in (None,):
                    continue
                comparable += 1
                if c.after.get(k) != bv:
                    mismatch = True
                    break
            if not mismatch and comparable >= 1:
                d.rename_to = c.address
                used.add(c.address)
                break


def analyze(plan: dict) -> dict:
    raw_changes = plan.get("resource_changes")
    if not isinstance(raw_changes, list):
        raw_changes = []
    changes = [Change(rc) for rc in raw_changes if isinstance(rc, dict)]
    global _LOCAL_ACCOUNT
    _LOCAL_ACCOUNT = _infer_local_account(changes)
    _pair_renames(changes)
    findings: list[Finding] = []
    for ch in changes:
        for rule in (rule_destructive, rule_safety, rule_network, rule_iam):
            try:
                findings.extend(rule(ch))
            except Exception as exc:  # a broken rule must not hide the rest of the report
                findings.append(Finding("WB-X000", "INFO", "analyzer", ch.address, ch.type, ch.kind,
                                        f"Rule {rule.__name__} failed", f"{type(exc).__name__}: {exc}",
                                        "Review this resource manually.", {}))
    findings.extend(rule_plan_level(plan, changes))
    findings.sort(key=lambda f: (SEV_RANK[f.severity], f.category, f.address))

    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    verdict = ("BLOCK" if counts["CRITICAL"] else "WARN" if counts["HIGH"]
               else "REVIEW" if counts["MEDIUM"] else "OK")
    summary = _summary(plan, changes)
    unflagged = _unflagged(changes, findings)
    return {"version": VERSION, "verdict": verdict, "counts": counts, "summary": summary,
            "findings": [f.to_dict() for f in findings], "unflagged": unflagged}


def _summary(plan: dict, changes: list[Change]) -> dict:
    managed = [c for c in changes if c.mode == "managed"]
    kinds = {}
    for c in managed:
        kinds[c.kind] = kinds.get(c.kind, 0) + 1
    providers = sorted({c.provider.rsplit("/", 1)[-1] for c in managed if c.provider})
    modules = sorted({c.raw.get("module_address") for c in managed if c.raw.get("module_address")})
    return {
        "terraform_version": plan.get("terraform_version"),
        "format_version": plan.get("format_version"),
        "resources_changing": sum(1 for c in managed if c.kind != "no-op"),
        "create": kinds.get("create", 0), "update": kinds.get("update", 0),
        "delete": kinds.get("delete", 0), "replace": kinds.get("replace", 0),
        "forget": kinds.get("forget", 0), "no_op": kinds.get("no-op", 0),
        "data_reads": sum(1 for c in changes if c.mode == "data" and c.kind == "read"),
        "providers": providers, "modules": modules[:20],
        "drift": len(plan.get("resource_drift") or []),
        "applyable": plan.get("applyable"), "complete": plan.get("complete"),
        "errored": plan.get("errored"),
        "outputs_changing": sum(1 for v in (plan.get("output_changes") or {}).values()
                                if isinstance(v, dict) and v.get("actions") not in (["no-op"], None))
        if isinstance(plan.get("output_changes"), dict) else 0,
        "imports": sum(1 for c in changes if c.importing),
    }


def _unflagged(changes: list[Change], findings: list[Finding]) -> list[dict]:
    flagged = {f.address for f in findings}
    out = []
    for c in changes:
        if c.mode != "managed" or c.kind == "no-op" or c.address in flagged:
            continue
        out.append({"address": c.address, "type": c.type, "action": c.kind})
    return out


# --------------------------------------------------------------------------- #
# Rendering                                                                     #
# --------------------------------------------------------------------------- #
VERDICT_TEXT = {
    "BLOCK": "do not apply until the critical findings are resolved or explicitly approved",
    "WARN": "apply only after the high-severity findings are understood and accepted",
    "REVIEW": "read the medium-severity findings before applying",
    "OK": "no critical, high, or medium findings",
}


def render_markdown(report: dict, source: str, max_findings: int) -> str:
    s = report["summary"]
    c = report["counts"]
    lines = []
    lines.append(f"# whatbreaks review — {report['verdict']}")
    lines.append("")
    plan_line = (f"**Plan:** {s['resources_changing']} resource(s) changing — "
                 f"{s['create']} to add, {s['update']} to change, {s['delete']} to destroy, "
                 f"{s['replace']} to replace" + (f", {s['forget']} to forget" if s['forget'] else "") + ".")
    meta = []
    if s.get("terraform_version"):
        meta.append(f"terraform {s['terraform_version']}")
    if s.get("providers"):
        meta.append("providers: " + ", ".join(s["providers"]))
    if s.get("modules"):
        meta.append(f"{len(s['modules'])} module(s)")
    if s.get("drift"):
        meta.append(f"{s['drift']} drifted")
    if meta:
        plan_line += " " + " · ".join(meta) + "."
    lines.append(plan_line)
    lines.append(f"**Source:** {source}")
    vtext = VERDICT_TEXT[report["verdict"]]
    if report["verdict"] == "OK" and (c["LOW"] or c["INFO"]):
        vtext += f"; {c['LOW']} low and {c['INFO']} info finding(s) worth a glance"
    lines.append(f"**Verdict:** {report['verdict']} — {vtext}. "
                 f"Findings: {c['CRITICAL']} critical, {c['HIGH']} high, {c['MEDIUM']} medium, "
                 f"{c['LOW']} low, {c['INFO']} info.")
    lines.append("")
    shown = 0
    for sev in SEVERITIES:
        group = [f for f in report["findings"] if f["severity"] == sev]
        if not group:
            continue
        lines.append(f"## {sev.title()} ({len(group)})")
        lines.append("")
        for f in group:
            if shown >= max_findings:
                break
            shown += 1
            lines.append(f"- **[{f['rule']}] {f['address']}** — {f['title']}")
            lines.append(f"  - What: {f['detail']}")
            lines.append(f"  - Fix: {f['fix']}")
        if shown >= max_findings:
            rest = len(report["findings"]) - shown
            if rest > 0:
                lines.append(f"- … {rest} more finding(s) omitted (raise --max-findings to see them)")
            break
        lines.append("")
    unf = report["unflagged"]
    if unf:
        lines.append(f"## Other changes ({len(unf)}, no findings)")
        lines.append("")
        by_action: dict[str, list[str]] = {}
        for u in unf:
            by_action.setdefault(u["action"], []).append(u["address"])
        for action in ("create", "update", "replace", "delete", "forget"):
            addrs = by_action.get(action)
            if not addrs:
                continue
            head = ", ".join(addrs[:12]) + (f", … +{len(addrs) - 12} more" if len(addrs) > 12 else "")
            lines.append(f"- {action}: {head}")
        lines.append("")
    if report.get("marker"):
        m = report["marker"]
        lines.append(f"_Review marker: {m['status']} ({m.get('path', '')})_")
    lines.append(f"_whatbreaks {VERSION} — deterministic rules; sensitive values are never printed._")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Markers (for the apply gate hook)                                             #
# --------------------------------------------------------------------------- #
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_marker(marker_dir: str, plan_file: str | None, json_sha: str, report: dict) -> dict:
    if not marker_dir or "${" in marker_dir:
        return {"status": "skipped (no marker directory available on this surface)"}
    try:
        os.makedirs(marker_dir, exist_ok=True)
    except OSError as exc:
        return {"status": f"skipped ({exc})"}
    key = sha256_file(plan_file) if plan_file else json_sha
    marker = {
        "plan_sha256": key,
        "keyed_by": "plan_file" if plan_file else "plan_json",
        "plan_file": os.path.abspath(plan_file) if plan_file else None,
        "json_sha256": json_sha,
        "verdict": report["verdict"],
        "counts": report["counts"],
        "reviewed_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "approved": False,
        "whatbreaks": VERSION,
    }
    path = os.path.join(marker_dir, key + ".json")
    if report["verdict"] == "BLOCK":
        marker["status"] = "blocked"
        status = ("verdict is BLOCK, so the apply gate will still deny `apply`; if the user reads the "
                  "critical findings and still wants to proceed, they must run `/whatbreaks:approve <plan-file>` "
                  "themselves (do not run it for them)")
    else:
        marker["status"] = "reviewed"
        status = "reviewed; the apply gate will allow `terraform apply` of this exact plan file"
    if not plan_file:
        status += " — NOTE: keyed by the JSON, not a binary plan file; pass --plan-file for the gate to match `terraform apply <file>`"
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(marker, fh, indent=2)
    except OSError as exc:
        return {"status": f"skipped ({exc})"}
    return {"status": status, "path": path, "plan_sha256": key}


# --------------------------------------------------------------------------- #
# CLI                                                                           #
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("plan_json", help="path to `terraform show -json` output, or - for stdin")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    ap.add_argument("--plan-file", help="the binary plan file the JSON was rendered from (for the apply gate)")
    ap.add_argument("--marker-dir", help="directory for review markers (usually ${CLAUDE_PLUGIN_DATA}/reviews)")
    ap.add_argument("--max-findings", type=int, default=60)
    ap.add_argument("--exit-code", action="store_true", help="exit 2 on BLOCK, 1 on WARN")
    args = ap.parse_args(argv)

    try:
        if args.plan_json == "-":
            raw = sys.stdin.buffer.read()
            source = "stdin"
        else:
            with open(args.plan_json, "rb") as fh:
                raw = fh.read()
            source = args.plan_json
    except OSError as exc:
        print(f"whatbreaks: cannot read plan: {exc}", file=sys.stderr)
        return 3
    try:
        plan = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        print("whatbreaks: input is not JSON. Render the plan with "
              "`terraform show -json <planfile> > plan.json` (or `tofu show -json`) and pass that file. "
              f"({exc})", file=sys.stderr)
        return 3
    if not isinstance(plan, dict) or "resource_changes" not in plan:
        if isinstance(plan, dict) and "values" in plan and "resource_changes" not in plan:
            print("whatbreaks: this looks like state JSON (`terraform show -json` with no plan file), "
                  "not a plan. Run `terraform plan -out=tfplan && terraform show -json tfplan > plan.json`.",
                  file=sys.stderr)
        else:
            print("whatbreaks: JSON has no `resource_changes`; is this a plan?", file=sys.stderr)
        return 3

    report = analyze(plan)
    json_sha = hashlib.sha256(raw).hexdigest()
    if args.plan_file and not os.path.isfile(args.plan_file):
        print(f"whatbreaks: --plan-file {args.plan_file} is not a file; no marker written", file=sys.stderr)
    elif args.marker_dir:
        report["marker"] = write_marker(args.marker_dir, args.plan_file, json_sha, report)

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(render_markdown(report, source if not args.plan_file else f"{source} (from {args.plan_file})",
                              args.max_findings))
    if args.exit_code:
        return {"BLOCK": 2, "WARN": 1}.get(report["verdict"], 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
