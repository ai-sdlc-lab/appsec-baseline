"""Every covered SR (TRACE) and every mitigation (THREAT) maps to a plan step with a named test
(SPEC-0001 §2.5 step 7, M-06).

Usage: crosscheck.py TRACE.md THREAT.md PLAN.md
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from plan import steps

COVERED = re.compile(r"^\|\s*(SR-[0-9]{3})\s*\|[^|]*\|\s*covered", re.MULTILINE)
MITIGATION = re.compile(r"^\|\s*(M-[0-9]{2})\s*\|", re.MULTILINE)


def required_ids(trace: str, threat: str) -> set[str]:
    section = threat.split("## Required mitigations", 1)[-1].split("\n## ", 1)[0]
    return set(COVERED.findall(trace)) | set(MITIGATION.findall(section))


def check(trace: str, threat: str, plan: str) -> list[str]:
    if "## Required mitigations" not in threat or not MITIGATION.search(threat.split("## Required mitigations", 1)[1]):
        return ["THREAT file has no 'Required mitigations' table with M-xx rows"]
    if not COVERED.search(trace):
        return ["TRACE file has no covered SR rows"]
    tested = set()
    for s in steps(plan):
        if s["tests"]:
            tested |= s["implements"]
    return [f"{i}: no plan step with a named test" for i in sorted(required_ids(trace, threat) - tested)]


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    errs = check(*(Path(p).read_text() for p in sys.argv[1:]))
    for e in errs:
        print(e)
    sys.exit(1 if errs else 0)
