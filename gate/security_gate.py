"""Deterministic security gate: allow / block / escalate.

LLM reviewers only produce findings; this script decides. It never trusts reviewer
output it cannot verify: a missing, unparseable, mislabelled or schema-invalid output
escalates to a human, it is never allowed.

Usage:
  security_gate.py --reviewer security-architect=out/architect.json \
                   --reviewer security-tester=out/tester.json \
                   --sarif out/semgrep.sarif [--summary "$GITHUB_STEP_SUMMARY"]
Exit code: 0 allow, 1 block, 2 escalate.
"""

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA = json.loads((Path(__file__).resolve().parent.parent / "schemas" / "findings.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)
BLOCKING_SEVERITIES = {"critical", "high"}
EXIT = {"allow": 0, "block": 1, "escalate": 2}


def _load(path: str | None):
    if path is None or not Path(path).is_file():
        return None, "missing"
    try:
        return json.loads(Path(path).read_text()), None
    except (OSError, ValueError) as e:
        return None, f"unparseable ({e.__class__.__name__})"


def evaluate(reviewers: dict[str, str | None], sarifs: list[str]) -> dict:
    escalate, block, notes = [], [], []

    for name, path in reviewers.items():
        doc, err = _load(path)
        if err:
            escalate.append(f"{name}: output {err}")
            continue
        errors = sorted(VALIDATOR.iter_errors(doc), key=lambda e: list(e.path))
        if errors:
            escalate.append(f"{name}: schema-invalid ({errors[0].message[:120]})")
            continue
        if doc["reviewer"] != name or any(f["reviewer"] != name for f in doc["findings"]):
            escalate.append(f"{name}: output labelled as a different reviewer")
            continue
        for f in doc["findings"]:
            ref = f"{name} {f['id']} [{f['severity']}] {f['sr_ref']} {f['file']}:{f['line'] or '-'}"
            if f.get("category") == "prompt-injection":
                escalate.append(f"{ref}: prompt-injection attempt reported")
            elif f["blocking"] or f["severity"] in BLOCKING_SEVERITIES:
                block.append(ref)
            else:
                notes.append(ref)

    for path in sarifs:
        doc, err = _load(path)
        if err or not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
            escalate.append(f"SARIF {path}: {err or 'not a SARIF log'}")
            continue
        for run in doc["runs"]:
            tool = run.get("tool", {}).get("driver", {}).get("name", "unknown")
            for r in run.get("results", []):
                # SARIF 2.1.0: absent level defaults to "warning".
                ref = f"{tool} {r.get('ruleId', '?')}"
                (block if r.get("level", "warning") == "error" else notes).append(ref)

    decision = "escalate" if escalate else "block" if block else "allow"
    return {"decision": decision, "escalate": escalate, "block": block, "notes": notes}


def _summary(result: dict) -> str:
    lines = [f"## security-gate: **{result['decision'].upper()}**", ""]
    for key in ("escalate", "block", "notes"):
        if result[key]:
            lines += [f"**{key}** ({len(result[key])})", *[f"- {x}" for x in result[key]], ""]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--reviewer", action="append", default=[], metavar="NAME=PATH", help="expected reviewer output")
    p.add_argument("--sarif", action="append", default=[], metavar="PATH")
    p.add_argument("--summary", help="append a markdown summary to this file")
    args = p.parse_args(argv)

    reviewers = {}
    for item in args.reviewer:
        name, _, path = item.partition("=")
        reviewers[name] = path or None
    if not reviewers and not args.sarif:
        p.error("nothing to evaluate")

    result = evaluate(reviewers, args.sarif)
    print(json.dumps(result, indent=2))
    if args.summary:
        with open(args.summary, "a") as fh:
            fh.write(_summary(result))
    return EXIT[result["decision"]]


if __name__ == "__main__":
    sys.exit(main())
