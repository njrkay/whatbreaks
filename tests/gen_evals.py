#!/usr/bin/env python3
"""Generate the `claude plugin eval` cases under evals/ from the fixture plans.

Each case gets a prompt.md that embeds the plan JSON the way a person would paste it,
a case.yaml that also exposes the fixture directory, and graders that check the verdict,
the resource named, the fix suggested, that the review skill produced the answer, and an
LLM rubric for the explanation. Re-run after changing fixtures or expectations.
"""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVALS = os.path.join(ROOT, "evals")

# case -> dict(prompt, verdict_regex, must_not_regex, resource_regex, fix_regex, rubric, tags)
CASES = {
    "rds-replace": dict(
        prompt="I'm about to apply this to production. I only changed the DB admin username. Is it safe?",
        verdict=r"(?i)\bBLOCK\b|\bcritical\b", resource=r"aws_db_instance\.main",
        fix=r"(?i)final snapshot|skip_final_snapshot|snapshot", tags=["smoke", "aws", "destructive"],
        rubric="PASS if the response says the RDS instance aws_db_instance.main will be replaced (destroyed and recreated) because master_username cannot be changed in place, warns that its data would be lost and that no final snapshot is taken, and tells the user not to apply as-is (or to take a backup / revert the change first). FAIL if it calls the plan safe, misses the replacement, or does not mention data loss."),
    "sg-open-ssh": dict(
        prompt="Quick sanity check on this plan before I apply — it's just an instance resize and a security group tweak.",
        verdict=r"(?i)\bBLOCK\b|\bcritical\b", resource=r"aws_security_group\.web",
        fix=r"(?i)bastion|session manager|ssm|restrict|specific (cidr|ip)|security group", tags=["smoke", "aws", "exposure"],
        rubric="PASS if the response flags that the security group change opens port 22 (SSH) to 0.0.0.0/0 (the whole internet) as the top risk and recommends restricting the source (bastion, SSM, VPN, or specific CIDRs), while treating the instance type change as low risk. FAIL if it misses the SSH exposure or treats the plan as safe."),
    "iam-admin-wildcard": dict(
        prompt="Review this plan for me. We're updating a deploy policy and attaching a policy to the CI role.",
        verdict=r"(?i)\bBLOCK\b|\bcritical\b", resource=r"aws_iam_policy\.deploy",
        fix=r"(?i)least.privilege|specific actions|scope|narrow", tags=["aws", "iam"],
        rubric="PASS if the response identifies that the deploy policy gains a statement allowing Action * on Resource * (full admin) and that AdministratorAccess is attached to the CI role, rates both as critical, and recommends scoping to specific actions/resources. FAIL if either is missed or the plan is called acceptable."),
    "count-shift": dict(
        prompt="Why does this plan destroy my three workers? I just switched them from count to for_each and didn't change anything else.",
        verdict=r"(?i)\bWARN\b|\bhigh\b", resource=r"aws_instance\.worker",
        fix=r"moved\s*\{|moved block|`moved`", tags=["smoke", "aws", "destructive"],
        rubric="PASS if the response explains that the destroy/create pairs are caused by the count-to-for_each address change (an index/key shift, not a real removal) and proposes `moved` blocks mapping each old index to its new key so nothing is recreated. FAIL if it treats the destroys as intended or does not mention moved blocks."),
    "clean-plan": dict(
        prompt="Anything risky in this plan? New Lambda plus a tag change.",
        verdict=r"(?i)\bOK\b|no (destructive|risky|dangerous)|safe|low.risk|nothing risky", must_not=r"verdict\W{0,12}(BLOCK|WARN)\b",
        resource=r"aws_lambda_function\.report", fix=None, tags=["smoke", "aws", "clean"],
        rubric="PASS if the response says the plan contains no destructive, exposing, or privilege-widening changes (only a Lambda and log group creation and a tag update) and gives an OK / safe-to-apply verdict without inventing risks. FAIL if it flags a critical or high risk or refuses to give a verdict."),
    "destroy-plan": dict(
        prompt="I ran plan in the prod directory and got this. Should I apply?",
        verdict=r"(?i)\bBLOCK\b|\bcritical\b", resource=r"aws_db_instance\.main",
        fix=r"(?i)workspace|state|backend|stop|do not apply|don't apply", tags=["smoke", "aws", "destructive"],
        rubric="PASS if the response recognises this as a destroy-everything plan (all six resources deleted, including the production database and a bucket with force_destroy), tells the user not to apply, and suggests checking the workspace/backend/state (a missing or wrong state is the likely cause). FAIL if it treats the deletions as routine."),
    "deletion-protection-off": dict(
        prompt="Small change to our Aurora cluster before the migration window. Fine to apply?",
        verdict=r"(?i)\bWARN\b|\bhigh\b", resource=r"aws_rds_cluster\.main",
        fix=r"(?i)deletion_protection|backup_retention", tags=["aws", "safety"],
        rubric="PASS if the response points out that deletion protection is being turned off and backup retention drops from 14 to 1 day on the production Aurora cluster, explains that this is what precedes a deletion, and advises keeping protection on until the deletion is actually intended. FAIL if it misses either change."),
    "gcp-sql-public": dict(
        prompt="Reviewing a teammate's GCP change: a firewall rule and a Cloud SQL network update. What breaks?",
        verdict=r"(?i)\bBLOCK\b|\bcritical\b", resource=r"google_sql_database_instance\.main",
        fix=r"(?i)0\.0\.0\.0/0|authorized_networks|private ip|auth proxy|iap", tags=["gcp", "exposure"],
        rubric="PASS if the response flags both the firewall rule allowing TCP 22 from 0.0.0.0/0 and the Cloud SQL authorized network 0.0.0.0/0 (database reachable from the internet) as critical, and recommends removing the open ranges (private IP / Cloud SQL Auth Proxy / IAP). FAIL if it misses the Cloud SQL exposure."),
    "azure-nsg-any": dict(
        prompt="Azure plan for a new NSG rule and a role assignment. Please review before I apply.",
        verdict=r"(?i)\bBLOCK\b|\bcritical\b", resource=r"azurerm_network_security_rule\.rdp",
        fix=r"(?i)bastion|specific|restrict|narrow(er)? scope|least", tags=["azure", "exposure", "iam"],
        rubric="PASS if the response flags RDP (3389) allowed inbound from any source and an Owner role assignment at subscription scope, both as critical, and recommends restricting the source (Azure Bastion / specific prefixes) and a narrower role and scope. FAIL if either is missed."),
    "trust-policy-public": dict(
        prompt="Two IAM role trust policy updates. Do these look right to you?",
        verdict=r"(?i)\bBLOCK\b|\bcritical\b", resource=r"aws_iam_role\.support",
        fix=r"(?i):sub\b|sub condition|ExternalId|PrincipalOrgID|specific (principal|account)", tags=["aws", "iam"],
        rubric="PASS if the response says the support role becomes assumable by any AWS principal (Principal AWS *) and that the GitHub OIDC role lost its sub condition so any GitHub repository could assume it, and gives fixes (name the principals; restore the token.actions.githubusercontent.com:sub condition). FAIL if either problem is missed."),
    "s3-public-block-off": dict(
        prompt="Marketing wants the assets bucket public. Here's the plan. Anything I should worry about?",
        verdict=r"(?i)\bBLOCK\b|\bcritical\b", resource=r"aws_s3_bucket_policy\.assets",
        fix=r"(?i)cloudfront|origin access|cdn|keep .* private", tags=["aws", "exposure"],
        rubric="PASS if the response explains that all four public-access-block settings are being disabled and a bucket policy grants s3:GetObject to everyone, flags this as public exposure, and suggests serving public content through CloudFront with Origin Access Control while keeping the bucket private (or at least confirming the exposure is intended). FAIL if it does not identify the public access."),
    "moved-rename": dict(
        prompt="I renamed the DynamoDB table resource in the code. The plan wants to destroy and create — is that expected?",
        verdict=r"(?i)\bBLOCK\b|\bcritical\b", resource=r"aws_dynamodb_table\.users",
        fix=r"moved\s*\{|moved block|`moved`", tags=["smoke", "aws", "destructive"],
        rubric="PASS if the response says the users table would be destroyed (losing its data) and recreated empty under the new address because the block was renamed without a `moved` block, and gives the exact moved block (from aws_dynamodb_table.users to aws_dynamodb_table.users_v2). FAIL if it accepts the destroy or omits the moved block."),
    "k8s-helm": dict(
        prompt="Helm/Kubernetes plan. We're moving to the v2 chart. What breaks?",
        verdict=r"(?i)\bBLOCK\b|\bcritical\b", resource=r"kubernetes_namespace\.prod",
        fix=r"(?i)moved|removed|namespace", tags=["kubernetes", "destructive"],
        rubric="PASS if the response flags that the prod namespace would be deleted (which deletes everything inside it) and that the Helm release is replaced because the chart changed (downtime), and treats the config map change as minor. FAIL if the namespace deletion is not the top finding."),
    "partial-plan-drift": dict(
        prompt="I planned with -target to just bump the Lambda memory. Good to go?",
        verdict=r"(?i)\bWARN\b|\bhigh\b|partial|-target", resource=r"aws_lambda_function\.api",
        fix=r"(?i)full (plan|terraform plan)|without -target|drift", tags=["aws", "plan-level"],
        rubric="PASS if the response notes that the plan is partial (built with -target) so dependent resources are not updated, mentions the drift (a security group changed outside Terraform and an instance no longer exists), and recommends a full plan afterwards. FAIL if it ignores the targeting or the drift."),
    "heuristics": dict(
        prompt="Mixed plan across a couple of providers. What's the risk here?",
        verdict=r"(?i)\bBLOCK\b|\bcritical\b", resource=r"cloudflare_zone\.example",
        fix=None, tags=["multi-provider", "destructive"],
        rubric="PASS if the response rates the Cloudflare zone deletion and the foo_database_cluster replacement as the serious risks (DNS outage; database data loss), the foo_widget deletion as moderate, and the null_resource replacement as harmless. FAIL if it rates the null_resource as serious or misses the zone/database."),
}

PASTED_TEXT_PROMPT = """Here's what terraform plan printed. Is it safe to apply?

```
Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  ~ update in-place
-/+ destroy and then create replacement

Terraform will perform the following actions:

  # aws_db_instance.main must be replaced
-/+ resource "aws_db_instance" "main" {
      ~ address                = "db-prod.abc123.us-east-1.rds.amazonaws.com" -> (known after apply)
      ~ arn                    = "arn:aws:rds:us-east-1:111111111111:db:db-prod" -> (known after apply)
        identifier             = "db-prod"
      ~ master_username        = "app" -> "appadmin" # forces replacement
        skip_final_snapshot    = true
        deletion_protection    = false
        backup_retention_period = 7
        # (30 unchanged attributes hidden)
    }

  # aws_lambda_function.api will be updated in-place
  ~ resource "aws_lambda_function" "api" {
        id                     = "api"
      ~ runtime                = "python3.11" -> "python3.12"
        # (20 unchanged attributes hidden)
    }

Plan: 1 to add, 1 to change, 1 to destroy.
```
"""


def write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")


def graders(case_dir: str, c: dict) -> None:
    g = os.path.join(case_dir, "graders")
    q = json.dumps  # JSON strings are valid double-quoted YAML scalars and escape backslashes/quotes safely

    def rx(pattern: str) -> str:
        # JavaScript regex has no inline (?i); the eval runner takes `flags: i` instead.
        return q(pattern.replace("(?i)", "")) + "\nflags: i"
    write(os.path.join(g, "verdict.md"), f"---\ntype: regex\npattern: {rx(c['verdict'])}\ntarget: last_message\n---\n")
    if c.get("must_not"):
        write(os.path.join(g, "no-false-alarm.md"),
              f"---\ntype: regex\npattern: {rx(c['must_not'])}\nmatch: not_contains\ntarget: last_message\n---\n")
    write(os.path.join(g, "resource-named.md"), f"---\ntype: regex\npattern: {rx(c['resource'])}\ntarget: last_message\n---\n")
    if c.get("fix"):
        write(os.path.join(g, "fix-suggested.md"), f"---\ntype: regex\npattern: {rx(c['fix'])}\ntarget: last_message\n---\n")
    skill_re = r'"skill"\s*:\s*"(?:[\w-]+:)?review"'
    write(os.path.join(g, "skill-fired.md"), "---\ntype: tool_used\ntool: Skill\ninput_match: " + q(skill_re) + "\n---\n")
    write(os.path.join(g, "rubric.md"), f"---\ntype: llm\nfocus: last_message\n---\n\n{c['rubric']}\n")


def main() -> int:
    for name, c in CASES.items():
        case_dir = os.path.join(EVALS, name)
        fixture = os.path.join(case_dir, "resources", "plan.json")
        with open(fixture, encoding="utf-8") as fh:
            plan_text = fh.read().strip()
        body = (f"{c['prompt']}\n\nThis is the output of `terraform show -json tfplan`:\n\n"
                f"```json\n{plan_text}\n```\n")
        front = (f"---\nname: {name}\ndescription: {json.dumps(c['prompt'])}\n"
                 f"tags: {json.dumps(c['tags'])}\nmax_turns: 15\ntimeout_seconds: 600\n"
                 f"allowed_tools: [Read, Glob, Grep, Skill, Bash, Write]\n---\n\n")
        write(os.path.join(case_dir, "prompt.md"), front + body)
        write(os.path.join(case_dir, "case.yaml"),
              f'schema_version: "1.1"\nname: {name}\ncontext:\n  add_dirs: [resources]\n')
        graders(case_dir, c)
        print(f"wrote evals/{name}")

    # pasted-text case (no fixture; manual review path)
    name = "pasted-text-plan"
    case_dir = os.path.join(EVALS, name)
    write(os.path.join(case_dir, "prompt.md"),
          f"---\nname: {name}\ndescription: Reviews a pasted human-readable plan without JSON.\n"
          f"tags: [\"smoke\", \"aws\", \"text\"]\nmax_turns: 10\ntimeout_seconds: 300\n"
          f"allowed_tools: [Read, Glob, Grep, Skill]\n---\n\n{PASTED_TEXT_PROMPT}")
    graders(case_dir, dict(
        verdict=r"(?i)\bBLOCK\b|\bcritical\b|do not apply|don't apply|not safe",
        resource=r"aws_db_instance|db-prod",
        fix=r"(?i)final snapshot|skip_final_snapshot|snapshot|revert",
        rubric="PASS if the response says the database instance is destroyed and recreated because master_username forces replacement, that skip_final_snapshot = true means no snapshot is left behind so the data is lost, and that the user should not apply as-is (revert the change, or back up first). FAIL if it calls the plan safe or misses the replacement."))
    print(f"wrote evals/{name}")
    write(os.path.join(EVALS, "README.md"), EVALS_README)
    return 0


EVALS_README = """# Eval suite

Run from the plugin root (uses your Claude credentials; see `claude plugin eval --help`):

```bash
claude plugin eval . --allow-tools Write "Bash(python3 *)"           # all cases, with/without-plugin comparison
claude plugin eval . --tag smoke --ablation none --allow-tools Write "Bash(python3 *)"   # quick check
```

One directory per case. `prompt.md` is what a person would type, with the plan JSON pasted in;
`resources/plan.json` is the same fixture (also used by `tests/test_fixtures.py`); `graders/`
holds the checks: the verdict word, the resource address, the fix phrase, that the `review` skill
fired, and an LLM rubric on the explanation. `pasted-text-plan` has no JSON and exercises the
manual review path.

Cases are generated by `tests/gen_evals.py`; edit that file rather than the case files.
"""


if __name__ == "__main__":
    sys.exit(main())
