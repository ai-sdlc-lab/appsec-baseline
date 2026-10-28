"""Deterministic gate: allow / block / questions / escalate (SPEC-0001 §1.3, §1.5, M-02, M-08, M-20).

LLM reviewers only produce findings; this script decides, and it sets each finding's status
(reviewers never do). It never trusts output it cannot verify: missing, unparseable, mislabelled,
schema-invalid or control-character-laden output escalates; it is never allowed.

Rules per finding:
- prompt-injection category                                   -> escalate
- security reviewer, sr_ref SR-xxx                            -> escalate, unless a valid exception matches (accepted-risk)
- security reviewer, sr_ref NEW and blocking / high / critical /
  needs_human / an "SR-nnn" in its text                       -> escalate, unless an exception with finding_id matches
- non-security reviewer, needs_human                          -> questions (the owner answers)
- other medium-or-worse or blocking findings                  -> block (the author fixes them)
- low / info, non-blocking                                    -> carried (kept as a note)
Decision: escalate > questions > block > allow.

Usage:
  security_gate.py --reviewer NAME=PATH [...] [--sarif PATH] [--repo dogs-app]
                   [--exceptions PATH] [--redactions N] [--summary FILE]
Exit code: 0 allow, 1 block, 2 escalate, 3 questions.
"""

import argparse
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "stage"))
import exceptions as exc

SCHEMA = json.loads((ROOT / "schemas" / "findings.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)
SECURITY = {
    "security-requirements-auditor",
    "security-architect",
    "security-code-reviewer",
    "workflow-iac-reviewer",
    "security-tester",
}
EXIT = {"allow": 0, "block": 1, "escalate": 2, "questions": 3}
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # \t and \n allowed
SR_IN_TEXT = re.compile(r"\bSR-[0-9]{3}\b")


def _load(path):
    if path is None or not Path(path).is_file():
        return None, "missing"
    try:
        return json.loads(Path(path).read_text()), None
    except (OSError, ValueError) as e:
        return None, f"unparseable ({e.__class__.__name__})"


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def classify(reviewer: str, f: dict, entries: list, repo: str) -> tuple[str, str | None]:
    """(status, exception id) where status is escalate | questions | block | carried | accepted-risk."""
    if f.get("category") == "prompt-injection":
        return "escalate", None
    sr = f["sr_ref"]
    serious = f["blocking"] or f["severity"] in ("high", "critical")
    text = f"{f['evidence']} {f['recommendation']}"
    security_relevant = reviewer in SECURITY or sr.startswith("SR-")
    if security_relevant and (
        sr.startswith("SR-") or (sr == "NEW" and (serious or f.get("needs_human") or SR_IN_TEXT.search(text)))
    ):
        hit = exc.match(entries, f, repo)
        return ("accepted-risk", hit) if hit else ("escalate", None)
    if f.get("needs_human"):
        return ("questions", None) if reviewer not in SECURITY else ("escalate", None)
    if serious or f["severity"] == "medium":
        return "block", None
    return "carried", None


def evaluate(reviewers: dict, sarifs: list, repo: str = "", exceptions_path=None, redactions: int = 0) -> dict:
    out = {k: [] for k in ("escalate", "questions", "block", "notes")}
    statuses = {}
    entries = exc.valid_entries(Path(exceptions_path)) if exceptions_path else exc.valid_entries()
    if redactions:
        out["escalate"].append(f"{redactions} credential-like string(s) redacted from reviewer output")

    for name, path in reviewers.items():
        doc, err = _load(path)
        if err:
            out["escalate"].append(f"{name}: output {err}")
            continue
        errors = sorted(VALIDATOR.iter_errors(doc), key=lambda e: list(e.path))
        if errors:
            out["escalate"].append(f"{name}: schema-invalid ({errors[0].message[:120]})")
            continue
        if any(_CONTROL.search(s) for s in _strings(doc)):
            out["escalate"].append(f"{name}: control characters in output")
            continue
        if doc["reviewer"] != name or any(f["reviewer"] != name for f in doc["findings"]):
            out["escalate"].append(f"{name}: output labelled as a different reviewer")
            continue
        for f in doc["findings"]:
            status, hit = classify(name, f, entries, repo)
            ref = f"{name} {f['id']} [{f['severity']}] {f['sr_ref']} {f['file']}:{f['line'] or '-'}"
            statuses[f"{name}/{f['id']}"] = {"status": status, "exception": hit}
            if status in ("escalate", "questions", "block"):
                out[status].append(ref)
            else:
                out["notes"].append(f"{ref} ({status}{' ' + hit if hit else ''})")

    for path in sarifs:
        doc, err = _load(path)
        if err or not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
            out["escalate"].append(f"SARIF {path}: {err or 'not a SARIF log'}")
            continue
        for run in doc["runs"]:
            tool = run.get("tool", {}).get("driver", {}).get("name", "unknown")
            for r in run.get("results", []):
                # SARIF 2.1.0: absent level defaults to "warning".
                ref = f"{tool} {r.get('ruleId', '?')}"
                (out["block"] if r.get("level", "warning") == "error" else out["notes"]).append(ref)

    decision = next((k for k in ("escalate", "questions", "block") if out[k]), "allow")
    return {"decision": decision, **out, "statuses": statuses}


def _summary(result: dict) -> str:
    sys.path.insert(0, str(ROOT / "stage"))
    from render import clean

    lines = [f"## security-gate: **{result['decision'].upper()}**", ""]
    for key in ("escalate", "questions", "block", "notes"):
        if result[key]:
            lines += [f"**{key}** ({len(result[key])})", *[f"- {clean(x)}" for x in result[key]], ""]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--reviewer", action="append", default=[], metavar="NAME=PATH", help="expected reviewer output")
    p.add_argument("--sarif", action="append", default=[], metavar="PATH")
    p.add_argument("--repo", default="")
    p.add_argument("--exceptions", help="sr-exceptions.yml (default: this checkout's)")
    p.add_argument("--redactions", type=int, default=0, help="number of redactions applied to reviewer output")
    p.add_argument("--summary", help="append a markdown summary to this file")
    args = p.parse_args(argv)

    reviewers = {}
    for item in args.reviewer:
        name, _, path = item.partition("=")
        reviewers[name] = path or None
    if not reviewers and not args.sarif:
        p.error("nothing to evaluate")

    result = evaluate(reviewers, args.sarif, args.repo, args.exceptions, args.redactions)
    print(json.dumps(result, indent=2))
    if args.summary:
        with open(args.summary, "a") as fh:
            fh.write(_summary(result))
    return EXIT[result["decision"]]


if __name__ == "__main__":
    sys.exit(main())
