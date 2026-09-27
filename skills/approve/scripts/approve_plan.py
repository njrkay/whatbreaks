#!/usr/bin/env python3
"""whatbreaks — record an explicit approval for a reviewed plan file.

The apply gate hook denies `terraform apply <planfile>` when the plan's review
verdict was BLOCK. After the person has read the critical findings and decided to
proceed anyway, this script marks that exact plan file (by SHA-256) as approved.

It refuses to approve a plan that has no review marker unless --force is given,
so an apply can't be waved through without a review ever having happened.

Standard library only. No network access.

Usage:
  approve_plan.py tfplan --marker-dir "$CLAUDE_PLUGIN_DATA/reviews" --reason "ticket OPS-123: planned migration"
  approve_plan.py tfplan --marker-dir DIR --revoke
  approve_plan.py --list --marker-dir DIR
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import sys


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("plan_file", nargs="?", help="the binary plan file that will be applied")
    ap.add_argument("--marker-dir", required=True, help="review marker directory (usually ${CLAUDE_PLUGIN_DATA}/reviews)")
    ap.add_argument("--reason", default="", help="why the risk is accepted (recorded in the marker)")
    ap.add_argument("--force", action="store_true", help="approve even if no review marker exists")
    ap.add_argument("--revoke", action="store_true", help="remove the approval (and review) for this plan file")
    ap.add_argument("--list", action="store_true", help="list markers in the directory")
    args = ap.parse_args(argv)

    if "${" in args.marker_dir:
        print("approve_plan: marker directory is not available on this surface (no plugin data dir); "
              "the apply gate only exists in Claude Code and Cowork.", file=sys.stderr)
        return 3

    if args.list:
        if not os.path.isdir(args.marker_dir):
            print("no markers")
            return 0
        rows = []
        for name in sorted(os.listdir(args.marker_dir)):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(args.marker_dir, name), encoding="utf-8") as fh:
                    m = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            rows.append(f"{str(m.get('plan_sha256') or '?')[:12]}  {str(m.get('status') or '?'):9} verdict={str(m.get('verdict') or '?'):6} "
                        f"approved={str(m.get('approved', False)).lower():5} {m.get('reviewed_at', '')}  {m.get('plan_file') or '(json only)'}")
        print("\n".join(rows) if rows else "no markers")
        return 0

    if not args.plan_file:
        ap.error("plan_file is required unless --list is given")
    if not os.path.isfile(args.plan_file):
        print(f"approve_plan: {args.plan_file} does not exist", file=sys.stderr)
        return 3

    key = sha256_file(args.plan_file)
    path = os.path.join(args.marker_dir, key + ".json")
    marker = None
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                marker = json.load(fh)
        except (OSError, json.JSONDecodeError):
            marker = None

    if args.revoke:
        if marker is None:
            print("approve_plan: nothing to revoke for this plan file")
            return 0
        os.remove(path)
        print(f"approve_plan: revoked review/approval for {args.plan_file} ({key[:12]}…). "
              f"Re-run the review before applying.")
        return 0

    if marker is None and not args.force:
        print("approve_plan: this plan file has not been reviewed (no marker). Run the review first "
              "(/whatbreaks:review <plan-file>); use --force only if the user explicitly insists.",
              file=sys.stderr)
        return 2

    os.makedirs(args.marker_dir, exist_ok=True)
    marker = marker or {"plan_sha256": key, "keyed_by": "plan_file", "verdict": "UNREVIEWED",
                        "counts": {}, "reviewed_at": None}
    marker.update({
        "plan_file": os.path.abspath(args.plan_file),
        "approved": True,
        "status": "approved",
        "approved_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "approval_reason": args.reason,
        "forced": bool(args.force and marker.get("verdict") == "UNREVIEWED"),
    })
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(marker, fh, indent=2)
    print(f"approve_plan: approved {args.plan_file} ({key[:12]}…) — verdict was {marker.get('verdict')}. "
          f"The apply gate will now allow `terraform apply {os.path.basename(args.plan_file)}` for this exact file. "
          f"Re-planning produces a different file and needs a new review.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
