# Resource catalog: how destroy and replace are rated

Generated from `scripts/analyze_plan.py` by `tests/gen_reference.py`. Do not edit by hand.

The analyzer rates a **delete** or **replace** of a managed resource by the tier of its type. Use the same tiers when reviewing a plan by hand (for example a pasted text plan).

| Tier | Delete / replace severity | Meaning |
|---|---|---|
| data | CRITICAL | Holds data, or holds the keys/backups that protect data. Recreating it loses what is stored. |
| outage | HIGH | A live endpoint, control, or dependency. Recreating it causes downtime, changes identifiers (IPs, DNS names, ARNs), or removes a protection. |
| default | MEDIUM | Not in the catalog, or a sub-resource (a policy, attachment, association, rule or setting attached to something else). Treat as medium impact until you know better. |
| versioned | replace LOW, delete MEDIUM | Revisioned by design (task definitions, secret versions, launch templates): a replace publishes a new version. |
| trivial | LOW | Carries no state and is cheap to recreate. |

## Heuristics for types not listed

A type absent from every list is rated by whole tokens of its name after the provider prefix (so `aws_route_table_association` is a sub-resource, not a `table`, and `vault_token` is not a vault):

- **default** if the name ends with a sub-resource suffix: `_policy`, `_iam_member`, `_iam_binding`, `_iam_policy`, `_association`, `_attachment`, `_configuration`, `_notification`, `_rule`, `_rules`, `_access_policy`, `_subnet_group`, `_option_group`, `_parameter_group`, `_event_subscription`, `_acl`, `_cors_configuration`, `_logging`, `_metric`, `_versioning`, `_website_configuration`, `_ownership_controls`, `_target`, `_lifecycle_configuration`, `_tag`, `_tags`, `_label`, `_labels`, `_setting`, `_settings`, `_route`, `_mapping`, `_permission`, `_permissions`, `_assignment`, `_member`, `_membership`, `_binding`, `_alias`, `_grant`, `_sink`, `_export`, `_condition`
- **data** if a token is one of: `backup`, `bigtable`, `bucket`, `cache`, `collection`, `database`, `datastore`, `db`, `disk`, `dynamodb`, `filesystem`, `firestore`, `index`, `keyspace`, `kms`, `ledger`, `snapshot`, `spanner`, `table`, `volume`, `warehouse`, or the name contains `file_system`, `storage_account`, `kms_key`, `crypto_key`, `key_ring`, `user_pool`
- **outage** if a token is one of: `address`, `api`, `app`, `certificate`, `cluster`, `deployment`, `distribution`, `domain`, `eip`, `endpoint`, `firewall`, `function`, `gateway`, `identity`, `instance`, `job`, `lb`, `network`, `pipeline`, `project`, `queue`, `registry`, `repository`, `role`, `secret`, `server`, `service`, `stream`, `subnet`, `topic`, `vm`, `vpc`, `workspace`, `zone`, or the name contains `node_pool`, `node_group`, `load_balancer`, `security_group`, `stateful_set`
- **trivial** if the name starts with: `random_`, `time_`, `local_`, `tls_`, `archive_`, `external_`, `http_`
- otherwise **default**.

## Data tier (CRITICAL)

**AWS:** `aws_acmpca_certificate_authority`, `aws_backup_plan`, `aws_backup_selection`, `aws_backup_vault`, `aws_cloudhsm_v2_cluster`, `aws_cognito_identity_pool`, `aws_cognito_user_pool`, `aws_datasync_task`, `aws_dax_cluster`, `aws_db_instance`, `aws_db_snapshot`, `aws_docdb_cluster`, `aws_dynamodb_global_table`, `aws_dynamodb_table`, `aws_ebs_snapshot`, `aws_ebs_volume`, `aws_efs_file_system`, `aws_elasticache_cluster`, `aws_elasticache_replication_group`, `aws_elasticache_serverless_cache`, `aws_elasticsearch_domain`, `aws_finspace_kx_environment`, `aws_fsx_lustre_file_system`, `aws_fsx_ontap_file_system`, `aws_fsx_openzfs_file_system`, `aws_fsx_windows_file_system`, `aws_glacier_vault`, `aws_keyspaces_keyspace`, `aws_keyspaces_table`, `aws_kms_external_key`, `aws_kms_key`, `aws_lightsail_database`, `aws_lightsail_disk`, `aws_memorydb_cluster`, `aws_msk_cluster`, `aws_msk_serverless_cluster`, `aws_neptune_cluster`, `aws_opensearch_domain`, `aws_opensearchserverless_collection`, `aws_organizations_account`, `aws_qldb_ledger`, `aws_rds_cluster`, `aws_rds_cluster_snapshot`, `aws_rds_global_cluster`, `aws_redshift_cluster`, `aws_redshiftserverless_namespace`, `aws_route53_zone`, `aws_s3_bucket`, `aws_s3_directory_bucket`, `aws_secretsmanager_secret`, `aws_storagegateway_gateway`, `aws_timestreamwrite_database`, `aws_timestreamwrite_table`, `aws_workspaces_directory`

**Google Cloud:** `google_alloydb_cluster`, `google_alloydb_instance`, `google_artifact_registry_repository`, `google_bigquery_dataset`, `google_bigquery_table`, `google_bigtable_instance`, `google_bigtable_table`, `google_compute_disk`, `google_compute_region_disk`, `google_dns_managed_zone`, `google_filestore_instance`, `google_firestore_database`, `google_kms_crypto_key`, `google_kms_key_ring`, `google_memorystore_instance`, `google_project`, `google_redis_cluster`, `google_redis_instance`, `google_secret_manager_secret`, `google_spanner_database`, `google_spanner_instance`, `google_sql_database`, `google_sql_database_instance`, `google_storage_bucket`

**Azure:** `azurerm_container_registry`, `azurerm_cosmosdb_account`, `azurerm_cosmosdb_mongo_database`, `azurerm_cosmosdb_sql_database`, `azurerm_data_lake_store`, `azurerm_dns_zone`, `azurerm_key_vault`, `azurerm_kusto_cluster`, `azurerm_log_analytics_workspace`, `azurerm_managed_disk`, `azurerm_mariadb_server`, `azurerm_mssql_database`, `azurerm_mssql_managed_instance`, `azurerm_mssql_server`, `azurerm_mysql_flexible_server`, `azurerm_mysql_server`, `azurerm_netapp_volume`, `azurerm_postgresql_flexible_server`, `azurerm_postgresql_server`, `azurerm_private_dns_zone`, `azurerm_recovery_services_vault`, `azurerm_redis_cache`, `azurerm_resource_group`, `azurerm_storage_account`, `azurerm_storage_container`, `azurerm_storage_share`, `azurerm_synapse_workspace`

**Kubernetes:** `kubernetes_namespace`, `kubernetes_namespace_v1`, `kubernetes_persistent_volume`, `kubernetes_persistent_volume_claim`, `kubernetes_persistent_volume_claim_v1`, `kubernetes_persistent_volume_v1`

**Other providers:** `cloudflare_d1_database`, `cloudflare_r2_bucket`, `cloudflare_zone`, `confluent_kafka_cluster`, `confluent_kafka_topic`, `digitalocean_database_cluster`, `digitalocean_spaces_bucket`, `digitalocean_volume`, `elasticstack_elasticsearch_index`, `github_organization`, `github_repository`, `gitlab_project`, `hcloud_volume`, `linode_volume`, `mongodbatlas_advanced_cluster`, `mongodbatlas_cluster`, `mssql_database`, `mysql_database`, `neon_project`, `planetscale_database`, `postgresql_database`, `snowflake_database`, `snowflake_schema`, `snowflake_table`, `supabase_project`, `vault_kv_secret`, `vault_kv_secret_v2`, `vault_mount`, `vsphere_datastore_cluster`

## Outage tier (HIGH)

**AWS:** `aws_acm_certificate`, `aws_alb`, `aws_amplify_app`, `aws_api_gateway_domain_name`, `aws_api_gateway_rest_api`, `aws_apigatewayv2_api`, `aws_apigatewayv2_domain_name`, `aws_appsync_graphql_api`, `aws_autoscaling_group`, `aws_batch_compute_environment`, `aws_bedrock_custom_model`, `aws_bedrockagent_agent`, `aws_bedrockagent_knowledge_base`, `aws_cloudfront_distribution`, `aws_cloudtrail`, `aws_cloudwatch_log_group`, `aws_codecommit_repository`, `aws_codepipeline`, `aws_config_configuration_recorder`, `aws_db_parameter_group`, `aws_db_subnet_group`, `aws_directory_service_directory`, `aws_dx_connection`, `aws_dx_gateway`, `aws_ec2_transit_gateway`, `aws_ec2_transit_gateway_attachment`, `aws_ecr_public_repository`, `aws_ecr_repository`, `aws_ecs_cluster`, `aws_ecs_service`, `aws_efs_mount_target`, `aws_eip`, `aws_eks_cluster`, `aws_eks_fargate_profile`, `aws_eks_node_group`, `aws_elasticache_subnet_group`, `aws_elb`, `aws_emr_cluster`, `aws_flow_log`, `aws_globalaccelerator_accelerator`, `aws_glue_catalog_database`, `aws_glue_catalog_table`, `aws_guardduty_detector`, `aws_iam_instance_profile`, `aws_iam_openid_connect_provider`, `aws_iam_role`, `aws_iam_saml_provider`, `aws_iam_user`, `aws_instance`, `aws_internet_gateway`, `aws_kinesis_firehose_delivery_stream`, `aws_kinesis_stream`, `aws_kms_alias`, `aws_lambda_function`, `aws_lb`, `aws_lb_listener`, `aws_lightsail_instance`, `aws_mq_broker`, `aws_nat_gateway`, `aws_network_acl`, `aws_organizations_organizational_unit`, `aws_organizations_policy`, `aws_organizations_policy_attachment`, `aws_rds_cluster_instance`, `aws_rds_cluster_parameter_group`, `aws_route`, `aws_route53_health_check`, `aws_route53_record`, `aws_route_table`, `aws_sagemaker_domain`, `aws_sagemaker_endpoint`, `aws_security_group`, `aws_securityhub_account`, `aws_service_discovery_service`, `aws_sfn_state_machine`, `aws_shield_protection`, `aws_sns_topic`, `aws_spot_instance_request`, `aws_sqs_queue`, `aws_subnet`, `aws_transfer_server`, `aws_vpc`, `aws_vpc_endpoint`, `aws_vpc_peering_connection`, `aws_vpn_connection`, `aws_vpn_gateway`, `aws_waf_web_acl`, `aws_wafv2_web_acl`, `aws_workspaces_workspace`

**Google Cloud:** `google_app_engine_application`, `google_cloud_run_service`, `google_cloud_run_v2_service`, `google_cloudfunctions2_function`, `google_cloudfunctions_function`, `google_composer_environment`, `google_compute_address`, `google_compute_firewall`, `google_compute_forwarding_rule`, `google_compute_global_address`, `google_compute_global_forwarding_rule`, `google_compute_ha_vpn_gateway`, `google_compute_instance`, `google_compute_instance_group_manager`, `google_compute_managed_ssl_certificate`, `google_compute_network`, `google_compute_region_instance_group_manager`, `google_compute_router`, `google_compute_router_nat`, `google_compute_security_policy`, `google_compute_ssl_certificate`, `google_compute_subnetwork`, `google_compute_vpn_gateway`, `google_container_cluster`, `google_container_node_pool`, `google_dataflow_job`, `google_dataproc_cluster`, `google_dns_record_set`, `google_folder`, `google_iam_workload_identity_pool`, `google_iam_workload_identity_pool_provider`, `google_kms_crypto_key_version`, `google_logging_organization_sink`, `google_logging_project_sink`, `google_memcache_instance`, `google_project_iam_audit_config`, `google_project_service`, `google_pubsub_subscription`, `google_pubsub_topic`, `google_secret_manager_secret_version`, `google_service_account`, `google_vertex_ai_endpoint`

**Azure:** `azurerm_api_management`, `azurerm_app_service`, `azurerm_application_gateway`, `azurerm_backup_policy_vm`, `azurerm_backup_protected_vm`, `azurerm_cdn_frontdoor_profile`, `azurerm_container_app`, `azurerm_container_app_environment`, `azurerm_data_factory`, `azurerm_databricks_workspace`, `azurerm_dns_a_record`, `azurerm_dns_cname_record`, `azurerm_eventhub_namespace`, `azurerm_express_route_circuit`, `azurerm_firewall`, `azurerm_front_door`, `azurerm_function_app`, `azurerm_key_vault_certificate`, `azurerm_key_vault_key`, `azurerm_kubernetes_cluster`, `azurerm_kubernetes_cluster_node_pool`, `azurerm_lb`, `azurerm_linux_function_app`, `azurerm_linux_virtual_machine`, `azurerm_linux_virtual_machine_scale_set`, `azurerm_linux_web_app`, `azurerm_management_group`, `azurerm_monitor_diagnostic_setting`, `azurerm_nat_gateway`, `azurerm_network_security_group`, `azurerm_policy_assignment`, `azurerm_private_endpoint`, `azurerm_public_ip`, `azurerm_role_assignment`, `azurerm_role_definition`, `azurerm_servicebus_namespace`, `azurerm_signalr_service`, `azurerm_subnet`, `azurerm_user_assigned_identity`, `azurerm_virtual_machine`, `azurerm_virtual_network`, `azurerm_virtual_network_gateway`, `azurerm_windows_function_app`, `azurerm_windows_virtual_machine`, `azurerm_windows_virtual_machine_scale_set`, `azurerm_windows_web_app`

**Kubernetes:** `kubernetes_cluster_role_binding`, `kubernetes_daemon_set_v1`, `kubernetes_daemonset`, `kubernetes_deployment`, `kubernetes_deployment_v1`, `kubernetes_ingress`, `kubernetes_ingress_v1`, `kubernetes_network_policy`, `kubernetes_secret`, `kubernetes_secret_v1`, `kubernetes_service`, `kubernetes_service_v1`, `kubernetes_stateful_set`, `kubernetes_stateful_set_v1`

**Helm:** `helm_release`

**Other providers:** `auth0_client`, `auth0_tenant`, `cloudflare_dns_record`, `cloudflare_record`, `cloudflare_tunnel`, `cloudflare_worker_script`, `cloudflare_zero_trust_tunnel_cloudflared`, `datadog_monitor`, `datadog_synthetics_test`, `digitalocean_droplet`, `digitalocean_kubernetes_cluster`, `digitalocean_loadbalancer`, `github_branch_protection`, `github_repository_ruleset`, `github_team`, `grafana_dashboard`, `hcloud_server`, `linode_instance`, `newrelic_alert_policy`, `okta_app_oauth`, `okta_group`, `opsgenie_service`, `pagerduty_escalation_policy`, `pagerduty_service`, `proxmox_vm_qemu`, `tfe_workspace`, `vault_auth_backend`, `vault_generic_secret`, `vault_policy`, `vsphere_virtual_machine`

## Versioned tier (replace LOW)

**AWS:** `aws_api_gateway_deployment`, `aws_apigatewayv2_deployment`, `aws_appconfig_hosted_configuration_version`, `aws_batch_job_definition`, `aws_ecs_task_definition`, `aws_imagebuilder_image`, `aws_lambda_alias`, `aws_lambda_layer_version`, `aws_launch_template`, `aws_sagemaker_model`, `aws_secretsmanager_secret_version`, `aws_ssm_document`, `aws_ssm_parameter`

**Google Cloud:** `google_cloud_run_v2_service_iam_binding`, `google_secret_manager_secret_version`

**Azure:** `azurerm_key_vault_secret`

## Trivial tier (LOW)

**AWS:** `aws_cloudwatch_dashboard`, `aws_ec2_tag`, `aws_lb_listener_certificate`

**Other providers:** `local_file`, `local_sensitive_file`, `null_resource`, `random_id`, `random_integer`, `random_pet`, `random_shuffle`, `random_string`, `random_uuid`, `terraform_data`, `time_offset`, `time_rotating`, `time_sleep`, `time_static`

## Ports treated as admin/database ports (open to 0.0.0.0/0 => CRITICAL)

21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 135 (RPC), 137 (NetBIOS), 138 (NetBIOS), 139 (NetBIOS), 445 (SMB), 1433 (MSSQL), 1434 (MSSQL), 1521 (Oracle), 2049 (NFS), 2181 (ZooKeeper), 2375 (Docker), 2376 (Docker), 2379 (etcd), 2380 (etcd), 3306 (MySQL), 3389 (RDP), 4505 (Salt), 4506 (Salt), 5432 (PostgreSQL), 5601 (Kibana), 5900 (VNC), 5984 (CouchDB), 5985 (WinRM), 5986 (WinRM), 6379 (Redis), 6443 (Kubernetes API), 7000 (Cassandra), 7001 (Cassandra), 8020 (HDFS), 8500 (Consul), 9000 (HDFS/MinIO), 9042 (Cassandra), 9092 (Kafka), 9200 (Elasticsearch), 9300 (Elasticsearch), 10250 (kubelet), 11211 (Memcached), 27017 (MongoDB), 27018 (MongoDB), 50070 (Hadoop)

Ports 80 and 443 alone are LOW (normal for an internet-facing endpoint); 3000, 8000, 8080, 8443, 8888 are HIGH (alternate web ports). ICMP alone is LOW. Any other port or a range of 100+ ports is HIGH. All ports / all protocols is CRITICAL.

## IAM actions treated as privilege-escalation capable

`cloudformation:createstack`, `glue:updatedevendpoint`, `iam:addusertogroup`, `iam:attachgrouppolicy`, `iam:attachrolepolicy`, `iam:attachuserpolicy`, `iam:createaccesskey`, `iam:createloginprofile`, `iam:createpolicy`, `iam:createpolicyversion`, `iam:deleterolepermissionsboundary`, `iam:deleteuserpermissionsboundary`, `iam:putgrouppolicy`, `iam:putrolepermissionsboundary`, `iam:putrolepolicy`, `iam:putuserpermissionsboundary`, `iam:putuserpolicy`, `iam:setdefaultpolicyversion`, `iam:updateassumerolepolicy`, `iam:updateloginprofile`, `lambda:createfunction`, `lambda:updatefunctioncode`, `sts:assumerole`

## Broad cloud roles

**GCP:** `roles/owner` (CRITICAL), `roles/editor` (HIGH), `roles/iam.securityAdmin` (HIGH), `roles/resourcemanager.projectIamAdmin` (HIGH), `roles/resourcemanager.organizationAdmin` (CRITICAL), `roles/iam.serviceAccountTokenCreator` (HIGH), `roles/iam.serviceAccountUser` (HIGH), `roles/iam.serviceAccountAdmin` (HIGH), `roles/iam.serviceAccountKeyAdmin` (HIGH), `roles/storage.admin` (MEDIUM), `roles/compute.admin` (MEDIUM), `roles/container.admin` (MEDIUM), `roles/cloudsql.admin` (MEDIUM), `roles/secretmanager.admin` (HIGH)

**Azure:** `owner` (CRITICAL at subscription/management-group scope, one level lower otherwise), `user access administrator` (CRITICAL at subscription/management-group scope, one level lower otherwise), `contributor` (HIGH at subscription/management-group scope, one level lower otherwise), `role based access control administrator` (CRITICAL at subscription/management-group scope, one level lower otherwise), `security admin` (HIGH at subscription/management-group scope, one level lower otherwise), `key vault administrator` (HIGH at subscription/management-group scope, one level lower otherwise), `storage account contributor` (MEDIUM at subscription/management-group scope, one level lower otherwise), `virtual machine contributor` (MEDIUM at subscription/management-group scope, one level lower otherwise)

## Rule identifiers

| Prefix | Family |
|---|---|
| `WB-D` | destructive: delete, replace, forget, rename detection |
| `WB-S` | safety mechanism weakened or control disabled |
| `WB-N` | network / public exposure |
| `WB-I` | IAM widening (`WB-I000` = pre-existing, not introduced by this plan) |
| `WB-P` | plan-level: errored, partial, destroy plan, blast radius, drift, imports |
| `WB-X` | the analyzer itself failed on a resource; review it by hand |
