"""Every test named in this repo's PLAN section ran and passed (SPEC-0001 §2.5 step 8, M-07, M-25).

The JUnit file comes from PR-controlled code, so it is parsed defensively: at most 5 MiB,
no DOCTYPE or entity declarations, any parse error fails. A test counts as passed if at least
one testcase with that name (parametrised variants included) passed and none failed.

Usage: named_tests.py PLAN.md REPO_NAME JUNIT.xml
"""

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from plan import steps

MAX_BYTES = 5 * 1024 * 1024
FORBIDDEN = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


class JUnitError(ValueError):
    pass


def results(junit: Path) -> dict[str, str]:
    """test name -> 'passed' | 'failed' (worst result wins)."""
    if not junit.is_file():
        raise JUnitError("JUnit report missing")
    raw = junit.read_bytes()
    if len(raw) > MAX_BYTES:
        raise JUnitError("JUnit report larger than 5 MiB")
    if FORBIDDEN.search(raw):
        raise JUnitError("JUnit report contains a DOCTYPE or entity declaration")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise JUnitError(f"JUnit report unparseable: {e}") from None
    out: dict[str, str] = {}
    for tc in root.iter("testcase"):
        name = (tc.get("name") or "").split("[", 1)[0]
        bad = any(child.tag in ("failure", "error") for child in tc)
        skipped = any(child.tag == "skipped" for child in tc)
        if bad:
            out[name] = "failed"
        elif not skipped and out.get(name) != "failed":
            out[name] = "passed"
    return out


def check(plan_text: str, repo: str, junit: Path) -> list[str]:
    try:
        res = results(junit)
    except JUnitError as e:
        return [str(e)]
    named = sorted({t for s in steps(plan_text, repo) for t in s["tests"]})
    errs = []
    for t in named:
        state = res.get(t)
        if state is None:
            errs.append(f"{t}: not found or skipped in the test run")
        elif state == "failed":
            errs.append(f"{t}: failed")
    return errs


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    errs = check(Path(sys.argv[1]).read_text(), sys.argv[2], Path(sys.argv[3]))
    for e in errs:
        print(e)
    sys.exit(1 if errs else 0)
