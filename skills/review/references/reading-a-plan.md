# Reading a Terraform / OpenTofu plan by hand

Use this when the analyzer script cannot run (no Python on the machine, or the person pasted
the human-readable plan text rather than JSON). The rules below are the same ones the script
applies; work through them in order and rate each finding with the tiers in
`resource-catalog.md`.

## 1. Plan JSON (`terraform show -json <planfile>`)

Top-level keys that matter:

| Key | What to look at |
|---|---|
| `resource_changes[]` | One entry per resource. `change.actions` tells you what happens; `change.before` / `change.after` are the old and new values. |
| `resource_changes[].action_reason` | Why Terraform chose the action (see table below). |
| `resource_changes[].change.replace_paths` | The attribute(s) forcing a replacement, as paths like `[["master_username"]]`. |
| `resource_changes[].change.after_unknown` | Attributes whose new value is only known after apply. A replacement driven by an unknown value is a warning sign. |
| `resource_changes[].change.before_sensitive` / `after_sensitive` | Which values are sensitive. **Never quote those values.** |
| `resource_changes[].deposed` | Set when the entry cleans up an object left behind by an earlier create-before-destroy. Low risk. |
| `resource_drift[]` | Resources that changed outside Terraform since the last apply. Same shape as `resource_changes`. |
| `output_changes` | Outputs that change; sensitive ones are flagged. |
| `complete` | `false` means `-target`/`-exclude` was used. The plan is partial. |
| `errored` | `true` means planning failed; nothing should be applied. |
| `applyable` | `false` when there is nothing to apply or the plan cannot be applied. |

### `change.actions` values

| `actions` | Meaning | Rate as |
|---|---|---|
| `["no-op"]` | Nothing changes | ignore |
| `["read"]` | A data source is read (often deferred to apply time) | ignore |
| `["create"]` | New resource | check exposure/IAM rules only |
| `["update"]` | In-place change | check safety/exposure/IAM rules |
| `["delete"]` | Destroyed | destructive: tier severity |
| `["delete","create"]` | **Replaced, delete first** — downtime between the two | destructive: tier severity; note the downtime |
| `["create","delete"]` | **Replaced, create first** (`create_before_destroy`) — shorter outage, but data on the old object is still lost | destructive: tier severity |
| `["forget"]` | Removed from state, left running (`removed` block) | LOW; the resource becomes unmanaged |

### `action_reason` values

| Reason | What it really means | Typical fix |
|---|---|---|
| `replace_because_cannot_update` | A ForceNew attribute changed (the one in `replace_paths`) | revert it, `ignore_changes`, or migrate data first |
| `replace_because_tainted` | Resource was tainted | `terraform untaint` if it is healthy |
| `replace_by_request` | `-replace=` flag was used | confirm the address |
| `replace_by_triggers` | `replace_triggered_by` fired | check the trigger |
| `delete_because_no_resource_config` | Block removed from config, **or renamed/moved without a `moved` block** | `moved` block if renamed; `removed` block to keep it running unmanaged |
| `delete_because_wrong_repetition` | Switched between `count`, `for_each`, and single instance | `moved` blocks per index/key |
| `delete_because_count_index` | `count` shrank or the list was reordered | `moved` blocks; prefer `for_each` with stable keys |
| `delete_because_each_key` | A `for_each` key was removed or renamed | `moved` block from old key to new |
| `delete_because_no_module` | The module call was removed | `moved` block into the new location, or confirm the removal |

**Rename detection:** a `delete` with `delete_because_no_resource_config` next to a `create` of the
same type whose `after` matches the deleted `before` (same name/identifier attributes) is almost
always a rename. Propose the exact `moved` block instead of letting it destroy and recreate.

## 2. Human-readable plan text (pasted from `terraform plan`)

Symbols at the start of each resource block:

| Symbol | Meaning |
|---|---|
| `+` | create |
| `~` | update in place |
| `-` | destroy |
| `-/+` | **replace** (destroy then create) |
| `+/-` | **replace** (create then destroy) |
| `<=` | data source read |

Phrases to search for, in priority order:

1. `must be replaced` and `forces replacement` — the attribute on the `# forces replacement` line is the cause.
2. `will be destroyed` — a plain delete. Look one line up for `# (because ...)`: `no longer in configuration`, `index ... out of range`, `key ... not in for_each` — these are rename/index-shift signals.
3. The summary line `Plan: X to add, Y to change, Z to destroy.` — if `to add` and `to change` are 0 and `to destroy` is everything, this is a destroy plan.
4. `(known after apply)` on an attribute that forces replacement.
5. `(sensitive value)` — never ask for or repeat the real value.
6. `Note: Objects have changed outside of Terraform` — the drift section.
7. `Warning: Resource targeting is in effect` — a partial plan.

Then apply the same checks as the JSON path: for each destroyed/replaced resource, rate by tier;
for updates, look for protection flags turning off (`deletion_protection`, `skip_final_snapshot`,
`force_destroy`, `backup_retention_period`, public-access-block flags, `enable_logging`), for
security-group / firewall / NSG rules gaining `0.0.0.0/0`, `::/0`, or `*` sources, and for IAM
documents gaining `"Action": "*"`, `"Resource": "*"`, `"Principal": "*"`, `NotAction`, `iam:PassRole`
on `*`, or admin managed policies.

## 3. Severity and verdict

| Severity | Use for |
|---|---|
| CRITICAL | Data loss (data-tier delete/replace), destroy plans, public database/bucket/role, admin-equivalent IAM, admin port open to the world, plan errored |
| HIGH | Outage-tier delete/replace, protections turned off, service-wide IAM wildcards, non-web ports open to the world, partial plan, large blast radius |
| MEDIUM | Default-tier delete/replace, reduced backups, cross-account trust, internet-facing LB, long-lived credentials |
| LOW | Trivial-tier delete/replace, public web ports only, `forget` |
| INFO | Drift summary, pre-existing issues not introduced by this plan |

Verdict: **BLOCK** if any CRITICAL; **WARN** if any HIGH; **REVIEW** if any MEDIUM; otherwise **OK**.

## 4. What not to do

- Do not run `terraform apply` or `terraform destroy` as part of a review. The review is read-only.
- Do not print sensitive values, even partially.
- Do not call a plan "safe" because it has no findings; say the automated rules found nothing destructive, exposing, or privilege-widening, and list what does change.
