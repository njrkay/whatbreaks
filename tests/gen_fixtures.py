#!/usr/bin/env python3
"""Generate the fixture plans used by the eval suite and the unit tests.

Each fixture is written to evals/<case>/resources/plan.json in the shape that
`terraform show -json <planfile>` produces (format_version 1.2). The plans are
hand-modelled on real provider schemas but contain no real account IDs, ARNs,
or secrets. Re-run this script after changing a fixture definition.
"""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVALS = os.path.join(ROOT, "evals")
ACCT = "111111111111"
TF_VERSION = "1.9.8"


def rc(address, rtype, actions, before=None, after=None, *, reason=None, replace_paths=None,
       after_unknown=None, sensitive=(), module=None, index=None, provider=None, mode="managed"):
    if provider is None:
        prefix = rtype.split("_", 1)[0]
        provider = {"aws": "registry.terraform.io/hashicorp/aws",
                    "google": "registry.terraform.io/hashicorp/google",
                    "azurerm": "registry.terraform.io/hashicorp/azurerm",
                    "kubernetes": "registry.terraform.io/hashicorp/kubernetes",
                    "helm": "registry.terraform.io/hashicorp/helm",
                    "cloudflare": "registry.terraform.io/cloudflare/cloudflare",
                    "random": "registry.terraform.io/hashicorp/random",
                    "null": "registry.terraform.io/hashicorp/null"}.get(prefix, f"registry.terraform.io/example/{prefix}")
    name = address.split(".")[-1].split("[")[0]
    entry = {
        "address": address,
        "mode": mode,
        "type": rtype,
        "name": name,
        "provider_name": provider,
        "change": {
            "actions": actions,
            "before": before,
            "after": after,
            "after_unknown": after_unknown if after_unknown is not None else ({"id": True} if after is not None and "id" not in (after or {}) else {}),
            "before_sensitive": {k: True for k in sensitive if before} if before else False,
            "after_sensitive": {k: True for k in sensitive if after} if after else False,
        },
    }
    if module:
        entry["module_address"] = module
    if index is not None:
        entry["index"] = index
    if replace_paths:
        entry["change"]["replace_paths"] = [[p] if isinstance(p, str) else p for p in replace_paths]
    if reason:
        entry["action_reason"] = reason
    return entry


def plan(changes, *, drift=None, complete=True, errored=False, outputs=None):
    root_resources = []
    for c in changes:
        if c["change"]["after"] is not None and c["mode"] == "managed":
            root_resources.append({
                "address": c["address"], "mode": "managed", "type": c["type"], "name": c["name"],
                "provider_name": c["provider_name"], "schema_version": 0, "values": c["change"]["after"],
                "sensitive_values": c["change"]["after_sensitive"] if isinstance(c["change"]["after_sensitive"], dict) else {},
            })
    p = {
        "format_version": "1.2",
        "terraform_version": TF_VERSION,
        "planned_values": {"root_module": {"resources": root_resources}},
        "resource_changes": changes,
        "output_changes": outputs or {},
        "configuration": {"provider_config": {}, "root_module": {}},
        "timestamp": "2026-09-26T10:00:00Z",
        "applyable": not errored and any(c["change"]["actions"] != ["no-op"] for c in changes),
        "complete": complete,
        "errored": errored,
    }
    if drift:
        p["resource_drift"] = drift
    return p


def sg_block(from_port, to_port, protocol, cidrs, desc=""):
    return {"cidr_blocks": cidrs, "description": desc, "from_port": from_port, "to_port": to_port,
            "protocol": protocol, "ipv6_cidr_blocks": [], "prefix_list_ids": [], "security_groups": [], "self": False}


# ----------------------------------------------------------------------------- fixtures
FIXTURES = {}

# 1. RDS replaced because master_username changed; no final snapshot; lambda update alongside
_rds_before = {"id": "db-prod", "identifier": "db-prod", "engine": "postgres", "engine_version": "16.3",
               "instance_class": "db.r6g.large", "allocated_storage": 200, "master_username": "app",
               "password": "REDACTED", "skip_final_snapshot": True, "deletion_protection": False,
               "backup_retention_period": 7, "multi_az": True, "publicly_accessible": False,
               "storage_encrypted": True, "tags": {"env": "prod"}}
_rds_after = dict(_rds_before, master_username="appadmin")
_rds_after.pop("id")
FIXTURES["rds-replace"] = plan([
    rc("aws_db_instance.main", "aws_db_instance", ["delete", "create"], _rds_before, _rds_after,
       reason="replace_because_cannot_update", replace_paths=["master_username"], sensitive=("password",),
       after_unknown={"id": True, "address": True, "endpoint": True}),
    rc("aws_lambda_function.api", "aws_lambda_function", ["update"],
       {"id": "api", "function_name": "api", "runtime": "python3.11", "memory_size": 256, "timeout": 10},
       {"id": "api", "function_name": "api", "runtime": "python3.12", "memory_size": 256, "timeout": 10},
       after_unknown={"last_modified": True}),
])

# 2. Security group gains SSH from the world (before: HTTPS only)
_sg_before = {"id": "sg-0abc", "name": "web", "vpc_id": "vpc-0abc",
              "ingress": [sg_block(443, 443, "tcp", ["0.0.0.0/0"], "https")],
              "egress": [sg_block(0, 0, "-1", ["0.0.0.0/0"])], "tags": {}}
_sg_after = dict(_sg_before, ingress=[sg_block(443, 443, "tcp", ["0.0.0.0/0"], "https"),
                                       sg_block(22, 22, "tcp", ["0.0.0.0/0"], "ssh for debugging")])
FIXTURES["sg-open-ssh"] = plan([
    rc("aws_security_group.web", "aws_security_group", ["update"], _sg_before, _sg_after),
    rc("aws_instance.web", "aws_instance", ["update"],
       {"id": "i-0abc", "instance_type": "t3.small", "ami": "ami-0abc", "tags": {"Name": "web"}},
       {"id": "i-0abc", "instance_type": "t3.medium", "ami": "ami-0abc", "tags": {"Name": "web"}}),
])

# 3. IAM policy widened to full admin
_pol_before = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Sid": "ReadArtifacts", "Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
     "Resource": ["arn:aws:s3:::example-artifacts", "arn:aws:s3:::example-artifacts/*"]}]})
_pol_after = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Sid": "ReadArtifacts", "Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
     "Resource": ["arn:aws:s3:::example-artifacts", "arn:aws:s3:::example-artifacts/*"]},
    {"Sid": "Temp", "Effect": "Allow", "Action": "*", "Resource": "*"}]})
FIXTURES["iam-admin-wildcard"] = plan([
    rc("aws_iam_policy.deploy", "aws_iam_policy", ["update"],
       {"id": f"arn:aws:iam::{ACCT}:policy/deploy", "name": "deploy", "policy": _pol_before},
       {"id": f"arn:aws:iam::{ACCT}:policy/deploy", "name": "deploy", "policy": _pol_after}),
    rc("aws_iam_role_policy_attachment.ci_admin", "aws_iam_role_policy_attachment", ["create"], None,
       {"role": "ci-runner", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
])

# 4. count -> for_each shift on instances: 3 destroy + 3 create of identical machines
_inst = lambda name: {"ami": "ami-0abc", "instance_type": "t3.micro", "subnet_id": "subnet-0abc",
                      "tags": {"Name": name}}
FIXTURES["count-shift"] = plan([
    rc("aws_instance.worker[0]", "aws_instance", ["delete"], dict(_inst("worker-0"), id="i-000"), None,
       reason="delete_because_wrong_repetition", index=0),
    rc("aws_instance.worker[1]", "aws_instance", ["delete"], dict(_inst("worker-1"), id="i-001"), None,
       reason="delete_because_wrong_repetition", index=1),
    rc("aws_instance.worker[2]", "aws_instance", ["delete"], dict(_inst("worker-2"), id="i-002"), None,
       reason="delete_because_wrong_repetition", index=2),
    rc('aws_instance.worker["a"]', "aws_instance", ["create"], None, _inst("worker-a"), index="a"),
    rc('aws_instance.worker["b"]', "aws_instance", ["create"], None, _inst("worker-b"), index="b"),
    rc('aws_instance.worker["c"]', "aws_instance", ["create"], None, _inst("worker-c"), index="c"),
])

# 5. Clean plan: new lambda + log group, tag update on a bucket
FIXTURES["clean-plan"] = plan([
    rc("aws_lambda_function.report", "aws_lambda_function", ["create"], None,
       {"function_name": "report", "runtime": "python3.12", "memory_size": 512, "timeout": 30,
        "role": f"arn:aws:iam::{ACCT}:role/report-lambda"}),
    rc("aws_cloudwatch_log_group.report", "aws_cloudwatch_log_group", ["create"], None,
       {"name": "/aws/lambda/report", "retention_in_days": 30}),
    rc("aws_s3_bucket.data", "aws_s3_bucket", ["update"],
       {"id": "example-data", "bucket": "example-data", "force_destroy": False, "tags": {"env": "prod"}},
       {"id": "example-data", "bucket": "example-data", "force_destroy": False, "tags": {"env": "prod", "owner": "data-team"}}),
    rc("data.aws_caller_identity.current", "aws_caller_identity", ["read"], None, {"account_id": ACCT}, mode="data"),
])

# 6. Destroy plan (missing state / wrong workspace / terraform destroy)
FIXTURES["destroy-plan"] = plan([
    rc("aws_vpc.main", "aws_vpc", ["delete"], {"id": "vpc-0abc", "cidr_block": "10.0.0.0/16"}, None),
    rc("aws_subnet.private", "aws_subnet", ["delete"], {"id": "subnet-0abc", "cidr_block": "10.0.1.0/24"}, None),
    rc("aws_security_group.app", "aws_security_group", ["delete"], {"id": "sg-0abc", "ingress": [], "egress": []}, None),
    rc("aws_instance.app", "aws_instance", ["delete"], {"id": "i-0abc", "instance_type": "t3.large"}, None),
    rc("aws_db_instance.main", "aws_db_instance", ["delete"], dict(_rds_before, skip_final_snapshot=True), None,
       sensitive=("password",)),
    rc("aws_s3_bucket.uploads", "aws_s3_bucket", ["delete"], {"id": "example-uploads", "bucket": "example-uploads", "force_destroy": True}, None),
])

# 7. Deletion protection off + backups reduced on an Aurora cluster
_cluster_before = {"id": "aurora-prod", "cluster_identifier": "aurora-prod", "engine": "aurora-postgresql",
                   "deletion_protection": True, "backup_retention_period": 14, "skip_final_snapshot": False,
                   "final_snapshot_identifier": "aurora-prod-final", "master_password": "REDACTED"}
_cluster_after = dict(_cluster_before, deletion_protection=False, backup_retention_period=1)
FIXTURES["deletion-protection-off"] = plan([
    rc("aws_rds_cluster.main", "aws_rds_cluster", ["update"], _cluster_before, _cluster_after,
       sensitive=("master_password",)),
])

# 8. GCP: firewall opens 22 to the world, Cloud SQL authorized network 0.0.0.0/0
FIXTURES["gcp-sql-public"] = plan([
    rc("google_compute_firewall.allow_ssh", "google_compute_firewall", ["create"], None,
       {"name": "allow-ssh", "network": "default", "direction": "INGRESS", "disabled": False,
        "source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ["22"]}], "deny": []}),
    rc("google_sql_database_instance.main", "google_sql_database_instance", ["update"],
       {"id": "main", "name": "main", "database_version": "POSTGRES_16", "deletion_protection": True,
        "settings": [{"tier": "db-custom-2-7680", "ip_configuration": [{"ipv4_enabled": True, "authorized_networks": []}]}]},
       {"id": "main", "name": "main", "database_version": "POSTGRES_16", "deletion_protection": True,
        "settings": [{"tier": "db-custom-2-7680", "ip_configuration": [{"ipv4_enabled": True,
                     "authorized_networks": [{"name": "office", "value": "203.0.113.0/24"},
                                             {"name": "anywhere", "value": "0.0.0.0/0"}]}]}]}),
])

# 9. Azure: NSG rule RDP from any + Owner at subscription scope
FIXTURES["azure-nsg-any"] = plan([
    rc("azurerm_network_security_rule.rdp", "azurerm_network_security_rule", ["create"], None,
       {"name": "allow-rdp", "priority": 100, "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
        "source_port_range": "*", "destination_port_range": "3389", "source_address_prefix": "*",
        "destination_address_prefix": "*", "resource_group_name": "rg-app", "network_security_group_name": "nsg-app"}),
    rc("azurerm_role_assignment.ci_owner", "azurerm_role_assignment", ["create"], None,
       {"scope": "/subscriptions/00000000-0000-0000-0000-000000000000", "role_definition_name": "Owner",
        "principal_id": "00000000-0000-0000-0000-000000000001"}),
])

# 10. Trust policies: role assumable by anyone; GitHub OIDC without sub condition
_trust_ok = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
    "Principal": {"AWS": f"arn:aws:iam::{ACCT}:root"}, "Action": "sts:AssumeRole"}]})
_trust_any = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
    "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]})
_gh_before = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
    "Principal": {"Federated": f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
                  "StringLike": {"token.actions.githubusercontent.com:sub": "repo:example/app:ref:refs/heads/main"}}}]})
_gh_after = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
    "Principal": {"Federated": f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}}]})
FIXTURES["trust-policy-public"] = plan([
    rc("aws_iam_role.support", "aws_iam_role", ["update"],
       {"id": "support", "name": "support", "assume_role_policy": _trust_ok},
       {"id": "support", "name": "support", "assume_role_policy": _trust_any}),
    rc("aws_iam_role.github_deploy", "aws_iam_role", ["update"],
       {"id": "github-deploy", "name": "github-deploy", "assume_role_policy": _gh_before},
       {"id": "github-deploy", "name": "github-deploy", "assume_role_policy": _gh_after}),
])

# 11. S3 public access block disabled + public bucket policy
_bp = json.dumps({"Version": "2012-10-17", "Statement": [{"Sid": "PublicRead", "Effect": "Allow",
    "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example-assets/*"}]})
FIXTURES["s3-public-block-off"] = plan([
    rc("aws_s3_bucket_public_access_block.assets", "aws_s3_bucket_public_access_block", ["update"],
       {"id": "example-assets", "bucket": "example-assets", "block_public_acls": True, "block_public_policy": True,
        "ignore_public_acls": True, "restrict_public_buckets": True},
       {"id": "example-assets", "bucket": "example-assets", "block_public_acls": False, "block_public_policy": False,
        "ignore_public_acls": False, "restrict_public_buckets": False}),
    rc("aws_s3_bucket_policy.assets", "aws_s3_bucket_policy", ["create"], None,
       {"bucket": "example-assets", "policy": _bp}),
])

# 12. Rename without a moved block: DynamoDB table destroyed and recreated under a new name
_ddb = {"name": "users", "billing_mode": "PAY_PER_REQUEST", "hash_key": "user_id",
        "attribute": [{"name": "user_id", "type": "S"}], "deletion_protection_enabled": False,
        "point_in_time_recovery": [{"enabled": True}], "tags": {"env": "prod"}}
FIXTURES["moved-rename"] = plan([
    rc("aws_dynamodb_table.users", "aws_dynamodb_table", ["delete"],
       dict(_ddb, id="users", arn=f"arn:aws:dynamodb:us-east-1:{ACCT}:table/users"), None,
       reason="delete_because_no_resource_config"),
    rc("aws_dynamodb_table.users_v2", "aws_dynamodb_table", ["create"], None, dict(_ddb),
       after_unknown={"id": True, "arn": True}),
])

# 13. Kubernetes namespace deleted + Helm release replaced
FIXTURES["k8s-helm"] = plan([
    rc("kubernetes_namespace.prod", "kubernetes_namespace", ["delete"],
       {"id": "prod", "metadata": [{"name": "prod", "labels": {"env": "prod"}}]}, None,
       reason="delete_because_no_resource_config"),
    rc("helm_release.app", "helm_release", ["delete", "create"],
       {"id": "app", "name": "app", "chart": "app", "repository": "https://charts.example.com", "version": "1.4.0", "namespace": "prod"},
       {"name": "app", "chart": "app-v2", "repository": "https://charts.example.com", "version": "2.0.0", "namespace": "prod"},
       reason="replace_because_cannot_update", replace_paths=["chart"]),
    rc("kubernetes_config_map.settings", "kubernetes_config_map", ["update"],
       {"id": "prod/settings", "data": {"LOG_LEVEL": "info"}}, {"id": "prod/settings", "data": {"LOG_LEVEL": "debug"}}),
])

# 14. Partial plan (-target) with drift
FIXTURES["partial-plan-drift"] = plan([
    rc("aws_lambda_function.api", "aws_lambda_function", ["update"],
       {"id": "api", "function_name": "api", "memory_size": 256}, {"id": "api", "function_name": "api", "memory_size": 512}),
], complete=False, drift=[
    rc("aws_security_group.web", "aws_security_group", ["update"], _sg_before, _sg_after),
    rc("aws_instance.old", "aws_instance", ["delete"], {"id": "i-0old", "instance_type": "t2.micro"}, None),
])

# 15. Catalog heuristics: known other-provider data resource, unknown provider with data-ish name, unknown default
FIXTURES["heuristics"] = plan([
    rc("cloudflare_zone.example", "cloudflare_zone", ["delete"], {"id": "z1", "zone": "example.com"}, None),
    rc("foo_database_cluster.main", "foo_database_cluster", ["delete", "create"],
       {"id": "c1", "name": "main", "size": "small"}, {"name": "main", "size": "large"},
       reason="replace_because_cannot_update", replace_paths=["size"]),
    rc("foo_widget.thing", "foo_widget", ["delete"], {"id": "w1"}, None),
    rc("null_resource.provisioner", "null_resource", ["delete", "create"], {"id": "1", "triggers": {"v": "1"}},
       {"triggers": {"v": "2"}}, reason="replace_because_cannot_update", replace_paths=["triggers"]),
])


def main() -> int:
    for name, p in FIXTURES.items():
        d = os.path.join(EVALS, name, "resources")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "plan.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(p, fh, indent=2)
            fh.write("\n")
        print(f"wrote {os.path.relpath(path, ROOT)} ({len(p['resource_changes'])} changes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
