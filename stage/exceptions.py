"""Accepted SR risks of one product repository: its own security/exceptions.yml (format: this repo's schema).

`errors()` checks the file strictly (the verifier fails on any error). `valid_entries()` is what the gate
uses: a malformed or expired entry counts as absent, so it can never accept a finding.
Agents add entries only with approved_by "agent" and at most AGENT_DAYS; the owner up to MAX_DAYS.

Usage: exceptions.py PATH   (exit 1 and list the errors if the file is invalid)
"""

import json
import sys
from datetime import date, timedelta
from fnmatch import fnmatchcase
from pathlib import Path

import jsonschema
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SCHEMA = json.loads((ROOT / "schemas" / "sr-exceptions.schema.json").read_text())
ITEM = jsonschema.Draft202012Validator(SCHEMA["items"])
MAX_DAYS = 180
AGENT_DAYS = 90


def _entry_errors(e) -> list[str]:
    errs = [m.message[:120] for m in ITEM.iter_errors(e)]
    if errs:
        return errs
    try:
        approved, expires = date.fromisoformat(e["approved"]), date.fromisoformat(e["expires"])
    except ValueError:
        return ["approved/expires is not a date"]
    limit = AGENT_DAYS if e["approved_by"] == "agent" else MAX_DAYS
    if expires < approved or expires - approved > timedelta(days=limit):
        errs.append(f"expires must be within {limit} days after approved")
    for p in e["paths"]:
        if "*" in p.split("/")[0] or p.startswith("**"):
            errs.append(f"top-level wildcard path not allowed: {p}")
    if e["sr"] == ["NEW"] and "finding_id" not in e:
        errs.append("an exception for a NEW finding needs finding_id")
    return errs


def load(path: Path):
    with open(path) as fh:
        data = yaml.safe_load(fh)
    return data if isinstance(data, list) else None


def errors(path: Path) -> list[str]:
    data = load(path)
    if data is None:
        return ["file is not a list of exceptions"]
    out, seen = [], set()
    for i, e in enumerate(data):
        eid = e.get("id", f"#{i}") if isinstance(e, dict) else f"#{i}"
        out += [f"{eid}: {m}" for m in _entry_errors(e)]
        if eid in seen:
            out.append(f"{eid}: duplicate id")
        seen.add(eid)
    return out


def valid_entries(path: Path, today: date | None = None) -> list[dict]:
    today = today or date.today()
    try:
        data = load(path) or []
    except (OSError, yaml.YAMLError):
        return []
    ids = [e.get("id") for e in data if isinstance(e, dict)]
    return [
        e
        for e in data
        if isinstance(e, dict)
        and not _entry_errors(e)
        and ids.count(e["id"]) == 1
        and date.fromisoformat(e["approved"]) <= today <= date.fromisoformat(e["expires"])
    ]


def match(entries: list[dict], finding: dict) -> str | None:
    """Exception id covering this finding, or None. Only low/medium/info findings can be covered."""
    if finding.get("severity") in ("high", "critical"):
        return None
    for e in entries:
        if finding.get("sr_ref") not in e["sr"]:
            continue
        if (finding.get("sr_ref") == "NEW" or "finding_id" in e) and e.get("finding_id") != finding.get("id"):
            continue
        if any(fnmatchcase(finding.get("file", ""), p) for p in e["paths"]):
            return e["id"]
    return None


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    errs = errors(Path(sys.argv[1]))
    for e in errs:
        print(e)
    sys.exit(1 if errs else 0)
