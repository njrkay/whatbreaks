#!/usr/bin/env python3
"""Run hooks/apply-gate.sh once with a synthetic PreToolUse payload and time it.

Usage: printf '%s' "$command" | python3 tests/run_hook.py HOOK CWD [--path DIR]

Prints one line, `<decision> <seconds>`, where decision is deny, allow,
deny-but-exit-N, allow-but-exit-N, invalid-json, or timeout. With --path the hook
runs with that PATH only (to exercise the paths without jq). A valid deny is a
JSON object with permissionDecision "deny" on stdout and exit status 2.
"""

import json
import os
import subprocess
import sys
import time


def main() -> int:
    hook, cwd = sys.argv[1], sys.argv[2]
    env = dict(os.environ)
    if len(sys.argv) > 4 and sys.argv[3] == "--path":
        env["PATH"] = sys.argv[4]
    command = sys.stdin.read()
    payload = json.dumps({
        "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "cwd": cwd, "tool_input": {"command": command},
    })
    t0 = time.time()
    try:
        proc = subprocess.run(["bash", hook], input=payload.encode("utf-8"),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=25)
    except subprocess.TimeoutExpired:
        print("timeout %.2f" % (time.time() - t0))
        return 0
    secs = time.time() - t0
    out = proc.stdout.decode("utf-8", "replace").strip()
    if out:
        try:
            data = json.loads(out)
            if data["hookSpecificOutput"]["permissionDecision"] != "deny":
                raise ValueError("not a deny")
        except Exception:
            print("invalid-json %.2f" % secs)
            return 0
        verdict = "deny" if proc.returncode == 2 else "deny-but-exit-%d" % proc.returncode
    else:
        verdict = "allow" if proc.returncode == 0 else "allow-but-exit-%d" % proc.returncode
    print("%s %.2f" % (verdict, secs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
