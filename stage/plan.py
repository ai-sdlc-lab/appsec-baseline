"""Parse PLAN-<NNNN>.md (SPEC-0001 §2.5 step 7): `## Repo: <name>` sections with a steps table
`| # | Files | Implements | Tests |`. Shared by crosscheck, plan_drift and named_tests."""

import re

ROW = re.compile(r"^\|\s*([A-Z]-[0-9]{2})\s*\|(.*)$")
TEST = re.compile(r"\btest_[A-Za-z0-9_]+")
CODE = re.compile(r"`([^`]+)`")


def _cells(rest: str) -> list[str]:
    return [c.strip() for c in rest.rstrip().rstrip("|").split("|")]


def steps(text: str, repo: str | None = None) -> list[dict]:
    """Steps of one repo section (or all sections when repo is None)."""
    out, current = [], None
    for line in text.splitlines():
        if line.startswith("## "):
            m = re.match(r"^## Repo: ([A-Za-z0-9._-]+)\s*$", line)
            current = m.group(1) if m else None
            continue
        m = ROW.match(line)
        if not m or current is None or (repo and current != repo):
            continue
        cells = _cells(m.group(2))
        if len(cells) < 3:
            continue
        files, implements, tests = cells[0], cells[1], cells[-1]
        out.append(
            {
                "id": m.group(1),
                "repo": current,
                "files": [f for f in CODE.findall(files) if "/" in f or "." in f],
                "implements": set(re.findall(r"SR-[0-9]{3}|M-[0-9]{2}", implements)),
                "tests": set(TEST.findall(tests)),
            }
        )
    return out
