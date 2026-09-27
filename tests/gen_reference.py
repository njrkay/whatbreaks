#!/usr/bin/env python3
"""Regenerate skills/review/references/resource-catalog.md from the analyzer's catalogs,
so the reference Claude reads in manual mode always matches the script."""

from __future__ import annotations

import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYZER = os.path.join(ROOT, "skills", "review", "scripts", "analyze_plan.py")
OUT = os.path.join(ROOT, "skills", "review", "references", "resource-catalog.md")

spec = importlib.util.spec_from_file_location("analyze_plan", ANALYZER)
ap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ap)  # type: ignore[union-attr]


def group(types: set[str]) -> dict[str, list[str]]:
    g: dict[str, list[str]] = {}
    for t in sorted(types):
        prefix = t.split("_", 1)[0]
        label = {"aws": "AWS", "google": "Google Cloud", "azurerm": "Azure", "kubernetes": "Kubernetes",
                 "helm": "Helm"}.get(prefix, "Other providers")
        g.setdefault(label, []).append(t)
    order = ["AWS", "Google Cloud", "Azure", "Kubernetes", "Helm", "Other providers"]
    return {k: g[k] for k in order if k in g}


def main() -> int:
    lines = ["# Resource catalog: how destroy and replace are rated", "",
             "Generated from `scripts/analyze_plan.py` by `tests/gen_reference.py`. Do not edit by hand.", "",
             "The analyzer rates a **delete** or **replace** of a managed resource by the tier of its type. "
             "Use the same tiers when reviewing a plan by hand (for example a pasted text plan).", "",
             "| Tier | Delete / replace severity | Meaning |", "|---|---|---|",
             "| data | CRITICAL | Holds data, or holds the keys/backups that protect data. Recreating it loses what is stored. |",
             "| outage | HIGH | A live endpoint, control, or dependency. Recreating it causes downtime, changes identifiers (IPs, DNS names, ARNs), or removes a protection. |",
             "| default | MEDIUM | Not in the catalog. Treat as medium impact until you know better. |",
             "| trivial | LOW | Carries no state and is cheap to recreate. |", "",
             "## Heuristics for types not listed", "",
             "A type absent from every list is rated by words in its name:", "",
             "- **data** if the name contains: " + ", ".join(f"`{w}`" for w in ap.HEURISTIC_DATA_WORDS),
             "- **outage** if the name contains: " + ", ".join(f"`{w}`" for w in ap.HEURISTIC_OUTAGE_WORDS),
             "- **trivial** if the name starts with: " + ", ".join(f"`{w}`" for w in ap.TRIVIAL_PREFIXES),
             "- otherwise **default**.", ""]
    for title, types in (("Data tier (CRITICAL)", ap.DATA_TYPES), ("Outage tier (HIGH)", ap.OUTAGE_TYPES),
                         ("Trivial tier (LOW)", ap.TRIVIAL_TYPES)):
        lines.append(f"## {title}")
        lines.append("")
        for provider, names in group(types).items():
            lines.append(f"**{provider}:** " + ", ".join(f"`{n}`" for n in names))
            lines.append("")
    lines += ["## Ports treated as admin/database ports (open to 0.0.0.0/0 => CRITICAL)", "",
              ", ".join(f"{p} ({n})" for p, n in sorted(ap.ADMIN_PORTS.items())), "",
              "Ports 80 and 443 alone are LOW (normal for an internet-facing endpoint). Any other port or a range "
              "of 100+ ports is HIGH. All ports / all protocols is CRITICAL.", "",
              "## IAM actions treated as privilege-escalation capable", "",
              ", ".join(f"`{a}`" for a in sorted(ap.ESCALATION_ACTIONS)), "",
              "## Broad cloud roles", "",
              "**GCP:** " + ", ".join(f"`{r}` ({s})" for r, s in ap.GCP_ADMIN_ROLES.items()), "",
              "**Azure:** " + ", ".join(f"`{r}` ({s} at subscription/management-group scope, one level lower otherwise)"
                                        for r, s in ap.AZURE_ADMIN_ROLES.items()), ""]
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"wrote {os.path.relpath(OUT, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
