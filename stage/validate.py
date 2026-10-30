"""Validate reviewer output and committed review reports (SPEC-0001 §2.2, SR-001, M-05).

Usage:
  validate.py output PATH      reviewer output (findings schema); prints redaction count
  validate.py report PATH      committed review report (review-report schema)
Exit 0 valid, 1 invalid (reason on stderr).
"""

import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "gate"))
sys.path.insert(0, str(ROOT / "stage"))
from common import SECURITY_REVIEWERS, sr_relevant
from redact import redact

OUTPUT = Draft202012Validator(json.loads((ROOT / "schemas" / "findings.schema.json").read_text()))
REPORT = Draft202012Validator(json.loads((ROOT / "schemas" / "review-report.schema.json").read_text()))
MAX_BYTES = 256 * 1024
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # tab and newline allowed


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _load(path: Path):
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError(f"larger than {MAX_BYTES} bytes")
    return json.loads(raw.decode("utf-8"))


def check(kind: str, path: Path) -> list[str]:
    try:
        doc = _load(path)
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return [f"unreadable: {e.__class__.__name__}"]
    validator = OUTPUT if kind == "output" else REPORT
    errs = [e.message[:160] for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.path))]
    if any(_CONTROL.search(s) for s in _strings(doc)):
        errs.append("control characters in strings")
    if kind == "report" and not errs:
        has_open = any(f["status"] == "open" for f in doc["findings"])
        if (doc["verdict"] == "open") != has_open:
            errs.append("verdict must be 'open' exactly when a finding is open")
        for f in doc["findings"]:
            if f["status"] == "accepted-risk" and "exception" not in f:
                errs.append(f"{f['id']}: accepted-risk without exception id")
            if f["sr_ref"].startswith("SR-") and f["status"] not in ("accepted-risk", "open"):
                errs.append(f"{f['id']}: SR finding must be accepted-risk with an exception, or open")
            if f["status"] == "accepted-risk" and f["severity"] in ("high", "critical"):
                errs.append(f"{f['id']}: a high or critical finding can't be accepted by an agent; it stays open")
            if f["status"] == "open" and f["severity"] not in ("high", "critical"):
                errs.append(f"{f['id']}: only high or critical findings stay open; fix it or add an exception")
            if f["status"] == "carried" and (
                f.get("blocking") or f.get("needs_human") or f["severity"] in ("high", "critical")
            ):
                errs.append(f"{f['id']}: blocking, high or needs-human finding can't be carried")
            if f["status"] == "carried" and sr_relevant(doc["reviewer"], f):
                errs.append(f"{f['id']}: the owner decides this finding; it can't be carried")
            if doc["reviewer"] in SECURITY_REVIEWERS and f["sr_ref"] == "N/A":
                errs.append(f"{f['id']}: a security reviewer must reference an SR or NEW")
    return errs


def redact_file(path: Path) -> int:
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"larger than {MAX_BYTES} bytes")
    text, n = redact(path.read_text())
    if n:
        path.write_text(text)
    return n


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("output", "report"):
        sys.exit(__doc__)
    p = Path(sys.argv[2])
    try:
        n = redact_file(p) if sys.argv[1] == "output" else 0
    except (OSError, ValueError) as e:
        sys.exit(f"input.rejected: {e}")
    errs = check(sys.argv[1], p)
    if n:
        errs.append(f"{n} credential-like string(s) redacted: list it as open in the final PR")
    for e in errs:
        print(e, file=sys.stderr)
    print(n)
    sys.exit(1 if errs else 0)
