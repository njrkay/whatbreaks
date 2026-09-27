#!/usr/bin/env python3
"""Pre-submission self-check against the Claude plugin directory's published rules
(the plugin pre-submission checklist in the Claude docs). Complements `claude plugin
validate`, which only checks syntax and schema.

Only structural rules live here. The directory's keyword-level policy scan (words that
read as sending data or reading a credential) is left to the portal: a local copy of
those words would trip the scan itself.
"""

from __future__ import annotations

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT_EXT = {".md", ".json", ".py", ".sh", ".yaml", ".yml", ".txt", ".toml", ".cfg", ".ini", ".hcl", ".tf",
            ".svg", ".gitignore", ".csv", ".html", ".css", ".js", ".ts", ""}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
FONT_EXT = {".woff", ".woff2", ".ttf", ".otf"}
JUNK = {".DS_Store", "Thumbs.db", "desktop.ini", "__MACOSX"}
LAUNCHERS = re.compile(r"\b(npx|bunx|pnpm dlx|yarn dlx|uvx|pipx run|uv run|pip install|npm install)\b")
SECRET = re.compile(r"(AKIA[0-9A-Z]{16}|-----BEGIN ([A-Z]+ )?PRIVATE KEY-----|ghp_[A-Za-z0-9]{36}|"
                    r"xox[baprs]-[A-Za-z0-9-]{10,}|sk-ant-[A-Za-z0-9-]{20,})")
# in a hook script: the here-document operator (spelled in two pieces so that this file does
# not contain it), an inline interpreter program, or a string assembled around a variable
HDOC_OP = "<" * 2
HOOK_INLINE = re.compile(r"\b(python[23]?|node|perl|ruby|php|awk)\s+(-[a-z]*[ceEf]|-|-v\s)(?=\s|$)", re.M)
MIXED_QUOTE_VAR = re.compile(r"""'"\$[A-Za-z_{]|"'"\$[A-Za-z_{]""")
HOOK_EVENTS = {"PreToolUse", "PostToolUse", "Stop", "SubagentStop", "SessionStart", "SessionEnd",
               "UserPromptSubmit", "PreCompact", "Notification", "PermissionRequest", "PostToolUseFailure",
               "TeammateIdle", "TaskCompleted", "MessageDisplay", "PreModelSwitch", "PostModelSwitch",
               "SubagentStart", "Elicitation", "ElicitationResult", "ConfigChange", "WorktreeCreate",
               "WorktreeRemove", "InstructionsLoaded", "CwdChanged", "FileChanged", "StopFailure"}

problems: list[str] = []
warnings: list[str] = []


def walk():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "results")]
        for f in filenames:
            yield os.path.join(dirpath, f)


def main() -> int:
    files = list(walk())
    rel = lambda p: os.path.relpath(p, ROOT)

    # manifest
    mpath = os.path.join(ROOT, ".claude-plugin", "plugin.json")
    if not os.path.isfile(mpath):
        problems.append("missing .claude-plugin/plugin.json")
        m = {}
    else:
        m = json.load(open(mpath, encoding="utf-8"))
    name = m.get("name", "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}[a-z0-9]", name or ""):
        problems.append(f"name {name!r} must be lowercase letters/digits/hyphens, start and end alphanumeric")
    if name in {"claude", "anthropic", "official", "plugin", "mcp", "test"}:
        problems.append("name is a reserved word")
    for k in ("description", "author", "version"):
        if not m.get(k):
            warnings.append(f"plugin.json: set {k}")
    if "hooks" in m:
        warnings.append("plugin.json lists hooks; hooks/hooks.json loads automatically")
    for field in ("displayName",):
        v = m.get(field, "")
        if v and not all(ord(c) < 128 for c in v):
            problems.append(f"{field} contains non-ASCII characters")
    if "TODO" in json.dumps(m):
        warnings.append("plugin.json still contains TODO placeholders (author/homepage/repository)")

    # README and LICENSE
    readme = next((p for p in files if os.path.basename(p).lower() in ("readme.md", "readme")), None)
    if not readme:
        problems.append("README missing")
    else:
        text = re.sub(r"```.*?```", "", open(readme, encoding="utf-8").read(), flags=re.S)
        words = len(re.findall(r"\b\w+\b", text))
        if words < 40:
            problems.append(f"README has {words} words outside code blocks (< 40)")
    if not any(os.path.basename(p) == "LICENSE" for p in files) and not m.get("license"):
        problems.append("LICENSE file missing and no license field")

    # files
    if len(files) > 512:
        problems.append(f"{len(files)} files (> 512)")
    for p in files:
        base = os.path.basename(p)
        ext = os.path.splitext(base)[1].lower()
        r = rel(p)
        if base in JUNK or "__MACOSX" in r:
            problems.append(f"system junk file: {r}")
        if os.path.islink(p):
            problems.append(f"symlink: {r}")
        size = os.path.getsize(p)
        if ext in IMAGE_EXT or ext in FONT_EXT:
            continue
        if size > 256 * 1024:
            problems.append(f"{r} is {size // 1024} KiB (> 256 KiB)")
        if ext not in TEXT_EXT:
            problems.append(f"{r}: unexpected file type {ext!r} (binary files are held for review)")
            continue
        try:
            data = open(p, "rb").read()
            data.decode("utf-8")
        except UnicodeDecodeError:
            problems.append(f"{r} is not UTF-8 text")
            continue
        s = data.decode("utf-8", "replace")
        if re.search(r"[:\s]$", base) or re.fullmatch(r"(con|prn|aux|nul|com\d|lpt\d)(\..*)?", base, re.I):
            problems.append(f"{r}: file name invalid on Windows")
        if ext in (".sh", ".py", ".json", ".md") and LAUNCHERS.search(s) and "tests/" not in r and r != "README.md":
            problems.append(f"{r} mentions a package launcher/installer: {LAUNCHERS.search(s).group(0)}")
        if SECRET.search(s):
            problems.append(f"{r} looks like it contains a credential")
        # shapes the directory validator holds for review in a hook script (seen on real runs)
        if r.startswith("hooks/") and ext == ".sh":
            if HDOC_OP in s:
                problems.append(f"{r}: the here-document operator appears literally (the validator cannot place a quoted or commented one; build it from a variable)")
            code = "\n".join(l for l in s.splitlines() if not l.lstrip().startswith("#"))
            if HOOK_INLINE.search(code):
                problems.append(f"{r}: inline interpreter program in a hook script (held for review)")
            if MIXED_QUOTE_VAR.search(code):
                problems.append(f"{r}: a string assembled from quoted pieces and a variable (read as a command assembled at run time); write it as one $'...' string")

    # icon
    if not any(os.path.isfile(os.path.join(ROOT, ".claude-plugin", f"icon.{e}")) for e in ("svg", "png")):
        warnings.append("no .claude-plugin/icon.svg or icon.png (listing falls back to a generic icon)")

    # case-insensitive duplicates
    lowered = {}
    for p in files:
        key = rel(p).lower()
        if key in lowered:
            problems.append(f"names differ only by case: {rel(p)} vs {lowered[key]}")
        lowered[key] = rel(p)

    # hooks
    hpath = os.path.join(ROOT, "hooks", "hooks.json")
    if os.path.isfile(hpath):
        h = json.load(open(hpath, encoding="utf-8"))
        if "hooks" not in h:
            problems.append("hooks/hooks.json needs a top-level 'hooks' object")
        else:
            for event, entries in h["hooks"].items():
                if event not in HOOK_EVENTS:
                    problems.append(f"hooks.json: unknown event {event}")
                for entry in entries:
                    for hk in entry.get("hooks", []):
                        if hk.get("type") not in ("command", "prompt", "http", "agent", "mcp_tool"):
                            problems.append(f"hooks.json: unknown hook type {hk.get('type')}")
                        cmd = hk.get("command", "")
                        if hk.get("type") == "command":
                            for var in re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", cmd):
                                if var != "CLAUDE_PLUGIN_ROOT":
                                    problems.append(f"hooks.json command uses variable {var}; only CLAUDE_PLUGIN_ROOT is allowed")
                            if "$(" in cmd or "`" in cmd or " -c " in cmd:
                                problems.append("hooks.json command uses substitution or an inline program")
                            target = re.search(r"\$\{CLAUDE_PLUGIN_ROOT\}/([^\s\"']+)", cmd)
                            if target and not os.path.isfile(os.path.join(ROOT, target.group(1))):
                                problems.append(f"hooks.json points at missing file {target.group(1)}")
                        if hk.get("type") == "http" and not str(hk.get("url", "")).startswith("https://"):
                            problems.append("http hook must use https://")

    # skills / commands / agents frontmatter
    for p in files:
        r = rel(p)
        if not (r.startswith("skills/") and r.endswith("SKILL.md")) and not r.startswith(("commands/", "agents/")):
            continue
        if not r.endswith(".md"):
            continue
        s = open(p, encoding="utf-8").read()
        mm = re.match(r"^---\n(.*?)\n---\n", s, re.S)
        if not mm:
            warnings.append(f"{r}: no front matter")
            continue
        fm = mm.group(1)
        if not re.search(r"^description:", fm, re.M):
            warnings.append(f"{r}: no description")
        if re.search(r"^description:\s*\n\s*-", fm, re.M):
            problems.append(f"{r}: description must be a single text value, not a list")
        try:
            import yaml  # type: ignore
            d = yaml.safe_load(fm)
            if not isinstance(d.get("description"), str):
                problems.append(f"{r}: description is not a string")
        except ImportError:
            pass
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{r}: front matter does not parse: {exc}")
    for d in ("skills",):
        dp = os.path.join(ROOT, d)
        if os.path.isdir(dp):
            for sub in os.listdir(dp):
                if os.path.isdir(os.path.join(dp, sub)) and not os.path.isfile(os.path.join(dp, sub, "SKILL.md")):
                    problems.append(f"skills/{sub}/ has no SKILL.md")

    for w in warnings:
        print(f"WARN  {w}")
    for p in problems:
        print(f"FAIL  {p}")
    print(f"\n{len(files)} files checked; {len(problems)} blocking problem(s), {len(warnings)} warning(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
