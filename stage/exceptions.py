"""Accepted SR risks (SPEC-0001 §2.4, M-12, M-20, M-23).

`errors()` checks the file strictly (appsec-baseline CI). `valid_entries()` is what the gate and
the verifier use: a malformed or expired entry counts as absent, so it can never accept a finding.

Usage: exceptions.py [PATH]   (exit 1 and list the errors if the file is invalid)
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
DEFAULT = ROOT / "exceptions" / "sr-exceptions.yml"
SCHEMA = json.loads((ROOT / "schemas" / "sr-exceptions.schema.json").read_text())
ITEM = jsonschema.Draft202012Validator(SCHEMA["items"])
MAX_DAYS = 180


def _entry_errors(e) -> list[str]:
    errs = [m.message[:120] for m in ITEM.iter_errors(e)]
    if errs:
        return errs
    try:
        approved, expires = date.fromisoformat(e["approved"]), date.fromisoformat(e["expires"])
    except ValueError:
        return ["approved/expires is not a date"]
    if expires < approved or expires - approved > timedelta(days=MAX_DAYS):
        errs.append(f"expires must be within {MAX_DAYS} days after approved")
    for p in e["paths"]:
        if "*" in p.split("/")[0] or p.startswith("**"):
            errs.append(f"top-level wildcard path not allowed: {p}")
    if e["sr"] == ["NEW"] and "finding_id" not in e:
        errs.append("an exception for a NEW finding needs finding_id")
    return errs


def load(path: Path = DEFAULT):
    with open(path) as fh:
        data = yaml.safe_load(fh)
    return data if isinstance(data, list) else None


def errors(path: Path = DEFAULT) -> list[str]:
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


def valid_entries(path: Path = DEFAULT, today: date | None = None) -> list[dict]:
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
        and today <= date.fromisoformat(e["expires"])
    ]


def match(entries: list[dict], finding: dict, repo: str) -> str | None:
    """Exception id covering this finding, or None."""
    for e in entries:
        if e["repo"] != repo or finding.get("sr_ref") not in e["sr"]:
            continue
        if finding.get("sr_ref") == "NEW" and e.get("finding_id") != finding.get("id"):
            continue
        if any(fnmatchcase(finding.get("file", ""), p) for p in e["paths"]):
            return e["id"]
    return None


if __name__ == "__main__":
    errs = errors(Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT)
    for e in errs:
        print(e)
    sys.exit(1 if errs else 0)
