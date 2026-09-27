#!/usr/bin/env python3
"""whatbreaks — make a Terraform/OpenTofu plan JSON safe and small enough to share.

Keeps only what a risk review needs (resource_changes, resource_drift, output_changes
and the plan flags), drops the bulky `configuration`, `planned_values` and `prior_state`
sections, and replaces every value the plan marks as sensitive — plus values under
well-known secret attribute names — with "[REDACTED]".

Standard library only. No network access.

Usage:
  redact_plan.py plan.json > plan.redacted.json
  redact_plan.py plan.json -o plan.redacted.json --mask-accounts --drop-noop
  terraform show -json tfplan | redact_plan.py - > plan.redacted.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

SECRET_NAME_RE = re.compile(
    r"(password|passwd|secret|token|private_key|privatekey|client_secret|master_password|"
    r"connection_string|access_key|secret_key|api_key|apikey|auth_token|bearer|credential|"
    r"session_token|shared_secret|preshared|psk|license_key|encryption_key|ssh_key|certificate_body|"
    r"cert_pem|key_pem|passphrase|db_password|admin_password|root_password)",
    re.I,
)
ACCOUNT_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")
KEEP_TOP = ("format_version", "terraform_version", "resource_changes", "resource_drift",
            "output_changes", "applyable", "complete", "errored", "timestamp", "checks")


class Redactor:
    def __init__(self, mask_accounts: bool):
        self.mask_accounts = mask_accounts
        self.masked = 0
        self.accounts: dict[str, str] = {}

    def value(self, v: Any, sens: Any, key: str = "") -> Any:
        """Redact v guided by the parallel sensitivity structure `sens`."""
        if sens is True or (key and SECRET_NAME_RE.search(key) and v not in (None, "", [], {}, False)):
            self.masked += 1
            return "[REDACTED]"
        if isinstance(v, dict):
            s = sens if isinstance(sens, dict) else {}
            return {k: self.value(x, s.get(k), k) for k, x in v.items()}
        if isinstance(v, list):
            s = sens if isinstance(sens, list) else []
            return [self.value(x, s[i] if i < len(s) else None, key) for i, x in enumerate(v)]
        if isinstance(v, str) and self.mask_accounts:
            return ACCOUNT_RE.sub(self._account, v)
        return v

    def _account(self, m: re.Match) -> str:
        acct = m.group(1)
        if acct not in self.accounts:
            self.accounts[acct] = f"ACCT{len(self.accounts) + 1:02d}{'0' * 6}"
        return self.accounts[acct]

    def change(self, rc: dict) -> dict:
        ch = rc.get("change") or {}
        out = dict(rc)
        new_ch = dict(ch)
        new_ch["before"] = self.value(ch.get("before"), ch.get("before_sensitive"))
        new_ch["after"] = self.value(ch.get("after"), ch.get("after_sensitive"))
        out["change"] = new_ch
        if self.mask_accounts:
            for k in ("address", "module_address"):
                if isinstance(out.get(k), str):
                    out[k] = ACCOUNT_RE.sub(self._account, out[k])
        return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("plan_json", help="path to `terraform show -json` output, or - for stdin")
    ap.add_argument("-o", "--output", help="write here instead of stdout")
    ap.add_argument("--mask-accounts", action="store_true", help="replace 12-digit account IDs with stable placeholders")
    ap.add_argument("--drop-noop", action="store_true", help="omit resource_changes whose only action is no-op")
    ap.add_argument("--keep", action="append", default=[], help="extra top-level key to keep (repeatable)")
    args = ap.parse_args(argv)

    try:
        raw = sys.stdin.buffer.read() if args.plan_json == "-" else open(args.plan_json, "rb").read()
        plan = json.loads(raw.decode("utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"redact_plan: cannot read plan JSON: {exc}", file=sys.stderr)
        return 3
    if not isinstance(plan, dict):
        print("redact_plan: top-level JSON is not an object", file=sys.stderr)
        return 3

    r = Redactor(args.mask_accounts)
    out: dict[str, Any] = {}
    for k in KEEP_TOP + tuple(args.keep):
        if k in plan:
            out[k] = plan[k]
    changes = []
    for rc in plan.get("resource_changes") or []:
        if not isinstance(rc, dict):
            continue
        if args.drop_noop and (rc.get("change") or {}).get("actions") == ["no-op"]:
            continue
        changes.append(r.change(rc))
    out["resource_changes"] = changes
    if plan.get("resource_drift"):
        out["resource_drift"] = [r.change(d) for d in plan["resource_drift"] if isinstance(d, dict)]
    oc = plan.get("output_changes")
    if isinstance(oc, dict):
        new_oc = {}
        for name, ch in oc.items():
            if not isinstance(ch, dict):
                continue
            c = dict(ch)
            c["before"] = r.value(ch.get("before"), ch.get("before_sensitive"), name)
            c["after"] = r.value(ch.get("after"), ch.get("after_sensitive"), name)
            new_oc[name] = c
        out["output_changes"] = new_oc
    out["whatbreaks_redacted"] = {"masked_values": r.masked, "accounts_masked": len(r.accounts),
                                  "dropped_sections": [k for k in plan if k not in out]}

    text = json.dumps(out, indent=1)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        sys.stdout.write(text + "\n")
    print(f"redact_plan: {len(raw):,} bytes -> {len(text):,} bytes; {r.masked} value(s) redacted; "
          f"{len(r.accounts)} account id(s) masked; {len(changes)} change(s) kept", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
