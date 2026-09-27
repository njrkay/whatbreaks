# Fix playbook

Concrete remediations for the findings the review produces. Give the person the snippet that
applies, adapted to their resource addresses. Every snippet is plain Terraform/OpenTofu; nothing
here requires extra tooling.

## Destructive changes

### A rename or move is about to destroy and recreate (`delete_because_no_resource_config`, `delete_because_no_module`)

```hcl
moved {
  from = aws_dynamodb_table.users
  to   = aws_dynamodb_table.users_v2
}

# into or out of a module
moved {
  from = aws_s3_bucket.logs
  to   = module.logging.aws_s3_bucket.logs
}
```

After adding the block, re-plan: the destroy/create pair should become a no-op (or an in-place
update). `moved` blocks need Terraform >= 1.1.

### Index or key shift (`delete_because_wrong_repetition`, `delete_because_count_index`, `delete_because_each_key`)

```hcl
# count -> for_each
moved {
  from = aws_instance.worker[0]
  to   = aws_instance.worker["a"]
}
moved {
  from = aws_instance.worker[1]
  to   = aws_instance.worker["b"]
}
```

Prefer `for_each` keyed by a stable identifier so future list edits do not shift indexes.

### Keep the resource running but stop managing it (Terraform >= 1.7)

```hcl
removed {
  from = aws_s3_bucket.archive
  lifecycle {
    destroy = false
  }
}
```

Older versions: `terraform state rm aws_s3_bucket.archive` (then delete the block). Both leave the
resource unmanaged, so nothing will ever destroy it through Terraform.

### Replacement forced by an attribute change (`replace_because_cannot_update`)

Options, in order of preference:

1. Revert the attribute if the change was not intended.
2. If the value changed outside Terraform and the live value is fine:
   ```hcl
   lifecycle {
     ignore_changes = [master_username]
   }
   ```
3. If the change is required on a data-tier resource: snapshot, then either restore into the new
   resource or do a blue-green cut-over. For AWS RDS use `snapshot_identifier` on the new instance.
   Note: a restore keeps the snapshot's master username, so a different admin login is better
   created in SQL than by replacing the instance.
4. Shorten the outage on outage-tier resources:
   ```hcl
   lifecycle {
     create_before_destroy = true
   }
   ```
   Check for name collisions first: many resources (an RDS `identifier`, a bucket name, a role
   name) cannot exist twice, and the create will fail unless the name is changed or generated.

### Tainted resource (`replace_because_tainted`)

```bash
terraform untaint aws_instance.app
```

### Protect resources that must never be destroyed by a plan

```hcl
lifecycle {
  prevent_destroy = true
}
```

This fails the plan (not the apply) when a destroy would occur, which is exactly what you want for
production databases, state buckets, and KMS keys.

### A destroy plan when you expected changes

Stop and check, in this order: the workspace (`terraform workspace show`), the backend/state file
the configuration points at, whether the state is empty or missing, and whether an empty or wrong
directory was planned. Never "fix" a missing state by applying; recover the state first
(`terraform state pull` from the correct backend, or restore a backup).

## Safety mechanisms

```hcl
# RDS / Aurora
deletion_protection       = true
skip_final_snapshot       = false
final_snapshot_identifier = "db-prod-final"   # a fixed name; rename/delete the old snapshot before a second destroy
backup_retention_period   = 7   # at or above the point-in-time restore window you need

# DynamoDB
deletion_protection_enabled = true
point_in_time_recovery { enabled = true }

# S3
force_destroy = false
resource "aws_s3_bucket_versioning" "x" {
  bucket = aws_s3_bucket.x.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_public_access_block" "x" {
  bucket                  = aws_s3_bucket.x.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# KMS
deletion_window_in_days = 30
enable_key_rotation     = true

# Cloud SQL
deletion_protection = true

# Azure Key Vault
purge_protection_enabled = true
soft_delete_retention_days = 90
```

## Network exposure

```hcl
# Restrict a security group rule to known sources
resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id            = aws_security_group.web.id
  ip_protocol                  = "tcp"
  from_port                    = 22
  to_port                      = 22
  referenced_security_group_id = aws_security_group.bastion.id   # instead of cidr_ipv4 = "0.0.0.0/0"
}
```

- Admin ports (22, 3389, database ports): no public listener at all. Use SSM Session Manager (AWS),
  IAP TCP forwarding (GCP), or Azure Bastion.
- Public web ports (80/443): terminate on a load balancer or CDN with TLS and a WAF, not on the
  instance's own security group.
- Databases: `publicly_accessible = false`; connect through the VPC, a bastion, or a proxy.
- GCP Cloud SQL: remove `0.0.0.0/0` from `authorized_networks`; prefer `private_network` and the
  Cloud SQL Auth Proxy.
- Azure NSG: replace `source_address_prefix = "*"` with specific prefixes or a service tag such as
  `VirtualNetwork` or `AzureLoadBalancer`.
- S3 public content: keep the bucket private and serve through CloudFront with Origin Access Control.

## IAM

```hcl
# Least-privilege statement instead of "*"
statement {
  sid       = "ReadArtifacts"
  actions   = ["s3:GetObject", "s3:ListBucket"]
  resources = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]
}

# iam:PassRole scoped to the roles that may be passed, and to the service that receives them
statement {
  actions   = ["iam:PassRole"]
  resources = [aws_iam_role.task.arn]
  condition {
    test     = "StringEquals"
    variable = "iam:PassedToService"
    values   = ["ecs-tasks.amazonaws.com"]
  }
}

# Trust policy: name the principal and add a condition
data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/deployer"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

# GitHub Actions OIDC: always constrain sub
condition {
  test     = "StringLike"
  variable = "token.actions.githubusercontent.com:sub"
  values   = ["repo:my-org/my-repo:ref:refs/heads/main"]   # or repo:...:environment:prod
}
condition {
  test     = "StringEquals"
  variable = "token.actions.githubusercontent.com:aud"
  values   = ["sts.amazonaws.com"]
}
```

- Replace `AdministratorAccess` / `PowerUserAccess` / `*FullAccess` attachments with a customer-managed
  policy. IAM Access Analyzer can generate one from CloudTrail activity.
- Keep `NotAction` / `NotResource` for `Deny` statements only.
- GCP: bind `roles/owner` and `roles/editor` to nothing but break-glass identities; grant
  `roles/iam.serviceAccountUser` on the specific service account, not the project. Prefer
  `google_*_iam_member` over authoritative `*_iam_policy`.
- Azure: `Owner` and `User Access Administrator` only at the narrowest scope, ideally through PIM.
- Static credentials (`aws_iam_access_key`, `google_service_account_key`): replace with roles or
  workload identity federation; if unavoidable, rotate and never expose them through outputs.

## The safe apply workflow (what the apply gate enforces)

```bash
terraform plan -out=tfplan            # or: tofu plan -out=tfplan
terraform show -json tfplan > plan.json
# review: /whatbreaks:review tfplan
terraform apply tfplan                # applies exactly what was reviewed
```

A saved plan is the only way to guarantee the apply does what the review looked at. Running
`terraform apply` again later re-plans against whatever changed in the meantime.
