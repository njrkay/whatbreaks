#!/usr/bin/env python3
"""Deterministic tests: run the analyzer over every fixture plan and check the verdict,
the findings that must be present, the findings that must be absent, and a few
phrases the fix text must contain. Runs with plain `python3 tests/test_fixtures.py`
or under pytest.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYZER = os.path.join(ROOT, "skills", "review", "scripts", "analyze_plan.py")
EVALS = os.path.join(ROOT, "evals")

spec = importlib.util.spec_from_file_location("analyze_plan", ANALYZER)
analyze_plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyze_plan)  # type: ignore[union-attr]

# case -> (verdict, must-have [(rule, address-substring, severity)], must-not-have [(rule, address-substring)], fix phrases)
EXPECT = {
    "rds-replace": ("BLOCK",
                    [("WB-D003", "aws_db_instance.main", "CRITICAL")],
                    [("WB-D001", "aws_lambda_function")],
                    {"aws_db_instance.main": ["master_username", "final snapshot"]}),
    "sg-open-ssh": ("BLOCK",
                    [("WB-N001", "aws_security_group.web", "CRITICAL")],
                    [("WB-N001", "aws_instance")],
                    {"aws_security_group.web": ["22", "0.0.0.0/0"]}),
    "iam-admin-wildcard": ("BLOCK",
                           [("WB-I001", "aws_iam_policy.deploy", "CRITICAL"),
                            ("WB-I002", "aws_iam_role_policy_attachment.ci_admin", "CRITICAL")],
                           [("WB-I000", "aws_iam_policy.deploy")],
                           {"aws_iam_policy.deploy": ["Action", "Resource"]}),
    "count-shift": ("WARN",
                    [("WB-D002", "aws_instance.worker[0]", "HIGH"),
                     ("WB-D002", "aws_instance.worker[2]", "HIGH")],
                    [("WB-D001", "aws_instance.worker")],
                    {"aws_instance.worker[0]": ["moved", "index"]}),
    "clean-plan": ("OK", [], [("WB-D001", ""), ("WB-D003", ""), ("WB-S001", ""), ("WB-N001", "")], {}),
    "destroy-plan": ("BLOCK",
                     [("WB-P003", "(plan)", "CRITICAL"),
                      ("WB-D001", "aws_db_instance.main", "CRITICAL"),
                      ("WB-D001", "aws_s3_bucket.uploads", "CRITICAL"),
                      ("WB-D001", "aws_vpc.main", "HIGH")],
                     [],
                     {"aws_s3_bucket.uploads": ["force_destroy"]}),
    "deletion-protection-off": ("WARN",
                                [("WB-S001", "aws_rds_cluster.main", "HIGH"),
                                 ("WB-S003", "aws_rds_cluster.main", "MEDIUM")],
                                [("WB-D001", ""), ("WB-D003", "")],
                                {}),
    "gcp-sql-public": ("BLOCK",
                       [("WB-N001", "google_compute_firewall.allow_ssh", "CRITICAL"),
                        ("WB-N004", "google_sql_database_instance.main", "CRITICAL")],
                       [],
                       {"google_sql_database_instance.main": ["0.0.0.0/0"]}),
    "azure-nsg-any": ("BLOCK",
                      [("WB-N001", "azurerm_network_security_rule.rdp", "CRITICAL"),
                       ("WB-I005", "azurerm_role_assignment.ci_owner", "CRITICAL")],
                      [],
                      {"azurerm_network_security_rule.rdp": ["3389"]}),
    "trust-policy-public": ("BLOCK",
                            [("WB-I001", "aws_iam_role.support", "CRITICAL"),
                             ("WB-I001", "aws_iam_role.github_deploy", "HIGH")],
                            [],
                            {"aws_iam_role.github_deploy": ["sub"]}),
    "s3-public-block-off": ("BLOCK",
                            [("WB-S001", "aws_s3_bucket_public_access_block.assets", "HIGH"),
                             ("WB-I001", "aws_s3_bucket_policy.assets", "CRITICAL")],
                            [],
                            {}),
    "moved-rename": ("BLOCK",
                     [("WB-D002", "aws_dynamodb_table.users", "CRITICAL")],
                     [("WB-D001", "aws_dynamodb_table.users_v2")],
                     {"aws_dynamodb_table.users": ["moved"]}),
    "k8s-helm": ("BLOCK",
                 [("WB-D002", "kubernetes_namespace.prod", "CRITICAL"),
                  ("WB-D003", "helm_release.app", "HIGH")],
                 [("WB-D001", "kubernetes_config_map")],
                 {}),
    "partial-plan-drift": ("WARN",
                           [("WB-P002", "(plan)", "HIGH"), ("WB-P005", "(plan)", "INFO")],
                           [("WB-D001", "")],
                           {}),
    "inline-admin-role": ("BLOCK",
                          [("WB-I001", "aws_iam_role.deploy", "CRITICAL")],
                          [("WB-I001", "aws_lambda_function")],
                          {"aws_iam_role.deploy": ["every action on every resource"]}),
    "managed-arns-admin": ("BLOCK",
                           [("WB-I002", "aws_iam_role.ci", "CRITICAL")], [], {"aws_iam_role.ci": ["AdministratorAccess"]}),
    "eks-endpoint-public": ("WARN",
                            [("WB-N003", "aws_eks_cluster.prod", "HIGH")], [], {"aws_eks_cluster.prod": ["0.0.0.0/0"]}),
    "guardduty-disabled": ("WARN",
                           [("WB-S010", "aws_guardduty_detector.main", "HIGH")], [], {}),
    "ecs-deploy-routine": ("OK",
                           [("WB-D003", "aws_ecs_task_definition.api", "LOW"),
                            ("WB-D003", "aws_secretsmanager_secret_version.api", "LOW")],
                           [("WB-D001", ""), ("WB-S001", "")], {}),
    "sns-sqs-scoped": ("OK",
                       [("WB-I001", "aws_sqs_queue_policy.orders", "LOW")], [], {"aws_sqs_queue_policy.orders": ["SourceArn"]}),
    "kms-default-policy": ("OK", [("WB-I001", "aws_kms_key.data", "INFO")],
                           [("WB-I002", ""), ("WB-S002", "")], {}),
    "gcp-binding-growth": ("BLOCK",
                           [("WB-I005", "google_project_iam_binding.owners", "CRITICAL")], [],
                           {"google_project_iam_binding.owners": ["eve@example.com"]}),
    "k8s-cluster-admin": ("BLOCK",
                          [("WB-I008", "kubernetes_cluster_role_binding.everyone", "CRITICAL")], [],
                          {"kubernetes_cluster_role_binding.everyone": ["system:authenticated"]}),
    "github-public": ("WARN", [("WB-N007", "github_repository.platform", "HIGH")], [], {}),
    "sub-resource-deletes": ("WARN",
                             [("WB-D002", "aws_route_table_association.private_a", "MEDIUM"),
                              ("WB-D002", "aws_s3_bucket_policy.logs", "MEDIUM"),
                              ("WB-P003", "(plan)", "HIGH")],
                             [("WB-D002", "aws_s3_bucket_policy.logs", "CRITICAL")] and [], {}),
    "heuristics": ("BLOCK",
                   [("WB-D001", "cloudflare_zone.example", "CRITICAL"),
                    ("WB-D003", "foo_database_cluster.main", "CRITICAL"),
                    ("WB-D001", "foo_widget.thing", "MEDIUM"),
                    ("WB-D003", "null_resource.provisioner", "LOW")],
                   [],
                   {}),
}


def run_case(name: str) -> tuple[bool, list[str]]:
    path = os.path.join(EVALS, name, "resources", "plan.json")
    with open(path, encoding="utf-8") as fh:
        plan = json.load(fh)
    report = analyze_plan.analyze(plan)
    verdict, must, must_not, phrases = EXPECT[name]
    problems: list[str] = []
    if report["verdict"] != verdict:
        problems.append(f"verdict {report['verdict']} != expected {verdict}")
    findings = report["findings"]
    for rule, addr, sev in must:
        hits = [f for f in findings if f["rule"] == rule and addr in f["address"]]
        if not hits:
            problems.append(f"missing {rule} on {addr!r}")
        elif not any(f["severity"] == sev for f in hits):
            problems.append(f"{rule} on {addr!r} has severity {[f['severity'] for f in hits]} != {sev}")
    for rule, addr in must_not:
        hits = [f for f in findings if f["rule"] == rule and addr in f["address"]]
        if hits:
            problems.append(f"unexpected {rule} on {addr!r}: {[f['title'] for f in hits]}")
    for addr, words in phrases.items():
        blob = " ".join(f["detail"] + " " + f["fix"] for f in findings if f["address"] == addr).lower()
        for w in words:
            if w.lower() not in blob:
                problems.append(f"finding text for {addr} lacks {w!r}")
    # sensitive values must never appear in the report
    md = analyze_plan.render_markdown(report, path, 100)
    if "REDACTED" in md:
        problems.append("sensitive value leaked into the markdown report")
    return (not problems), problems


def test_all_fixtures():
    failures = {}
    for name in EXPECT:
        ok, problems = run_case(name)
        if not ok:
            failures[name] = problems
    assert not failures, json.dumps(failures, indent=2)


def test_cli_exit_codes():
    block = subprocess.run([sys.executable, ANALYZER, os.path.join(EVALS, "destroy-plan", "resources", "plan.json"),
                            "--exit-code"], capture_output=True, text=True)
    assert block.returncode == 2, block.stderr
    ok = subprocess.run([sys.executable, ANALYZER, os.path.join(EVALS, "clean-plan", "resources", "plan.json"),
                         "--exit-code", "--format", "json"], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["verdict"] == "OK"
    bad = subprocess.run([sys.executable, ANALYZER, "-"], input="not json", capture_output=True, text=True)
    assert bad.returncode == 3 and "not JSON" in bad.stderr


def test_every_fixture_has_expectations():
    cases = sorted(d for d in os.listdir(EVALS)
                   if os.path.isfile(os.path.join(EVALS, d, "resources", "plan.json")))
    missing = [c for c in cases if c not in EXPECT]
    assert not missing, f"fixtures without expectations: {missing}"


if __name__ == "__main__":
    total = 0
    bad = 0
    for case in EXPECT:
        total += 1
        ok, problems = run_case(case)
        print(f"{'PASS' if ok else 'FAIL'}  {case}")
        for p in problems:
            bad += 1
            print(f"      - {p}")
    try:
        test_cli_exit_codes()
        print("PASS  cli exit codes")
    except AssertionError as exc:
        bad += 1
        print(f"FAIL  cli exit codes: {exc}")
    try:
        test_every_fixture_has_expectations()
        print("PASS  all fixtures covered")
    except AssertionError as exc:
        bad += 1
        print(f"FAIL  {exc}")
    print(f"\n{total} fixture cases, {bad} problem(s)")
    sys.exit(1 if bad else 0)
