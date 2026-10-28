"""Changed files of a code PR must be listed in this repo's PLAN section (SPEC-0001 §2.5 step 8, M-11).

A plan entry is a path or a glob (`stage/tests/**`); `**` matches across directories. Files of the
change's own folder (`docs/specs/<NNNN>-<slug>/`) are always allowed: the plan and the code-stage
reports live there.

Usage: plan_drift.py PLAN.md REPO_NAME CHANGE_DIR PATH...
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from plan import steps


def _glob(entry: str) -> re.Pattern:
    out = ""
    i = 0
    while i < len(entry):
        if entry.startswith("**", i):
            out += ".*"
            i += 2
        elif entry[i] == "*":
            out += "[^/]*"
            i += 1
        else:
            out += re.escape(entry[i])
            i += 1
    return re.compile(f"^{out}$")


def check(plan_text: str, repo: str, change_dir: str, paths: list[str]) -> list[str]:
    patterns = [
        _glob(f.rstrip("/") + ("/**" if f.endswith("/") else "")) for s in steps(plan_text, repo) for f in s["files"]
    ]
    prefix = change_dir.rstrip("/") + "/"
    return [
        f"{p}: not listed in the {repo} section of the plan"
        for p in paths
        if not p.startswith(prefix) and not any(r.match(p) for r in patterns)
    ]


if __name__ == "__main__":
    if len(sys.argv) < 5:
        sys.exit(__doc__)
    errs = check(Path(sys.argv[1]).read_text(), sys.argv[2], sys.argv[3], sys.argv[4:])
    for e in errs:
        print(e)
    sys.exit(1 if errs else 0)
