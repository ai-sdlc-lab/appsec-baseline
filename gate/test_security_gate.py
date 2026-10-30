import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import security_gate as gate

R = "security-architect"
C = "intent-completeness"


def finding(reviewer=R, **over):
    f = {
        "id": "ARC-001",
        "reviewer": reviewer,
        "severity": "medium",
        "sr_ref": "SR-015",
        "file": "docs/specs/0001-upload/SPEC-0001.md",
        "line": 12,
        "evidence": "Spec says 'any user may delete any photo' (line 12).",
        "recommendation": "Restrict delete to the owner.",
        "blocking": False,
    }
    return f | over


@pytest.fixture
def write(tmp_path):
    def _write(doc, name="out.json"):
        p = tmp_path / name
        p.write_text(doc if isinstance(doc, str) else json.dumps(doc))
        return str(p)

    return _write


@pytest.fixture
def no_exceptions(tmp_path):
    p = tmp_path / "exc.yml"
    p.write_text("[]\n")
    return str(p)


def run(reviewers=None, sarifs=(), exceptions=None, repo="dogs-app", redactions=0):
    return gate.evaluate(reviewers or {}, list(sarifs), repo, exceptions, redactions)


def test_clean_output_allows(write, no_exceptions):
    assert run({R: write({"reviewer": R, "findings": []})}, exceptions=no_exceptions)["decision"] == "allow"


@pytest.mark.parametrize(
    "over", [{"severity": "low"}, {"severity": "info"}, {"severity": "medium"}, {"blocking": True}]
)
def test_gate_escalates_any_sr_finding(write, no_exceptions, over):
    r = run({R: write({"reviewer": R, "findings": [finding(**over)]})}, exceptions=no_exceptions)
    assert r["decision"] == "escalate"


def _exceptions(tmp_path, expires="2026-12-31", today_ok=True):
    p = tmp_path / "e.yml"
    p.write_text(
        yaml.safe_dump(
            [
                {
                    "id": "EXC-001",
                    "sr": ["SR-015"],
                    "paths": ["docs/specs/0001-upload/SPEC-0001.md"],
                    "reason": "Accepted for the demo.",
                    "approved_by": "owner",
                    "approved": "2026-10-27",
                    "expires": expires,
                }
            ]
        )
    )
    return str(p)


def test_gate_accepts_matching_unexpired_exception(write, tmp_path, monkeypatch):
    monkeypatch.setattr(
        gate.exc,
        "date",
        type(
            "D",
            (),
            {
                "today": staticmethod(lambda: __import__("datetime").date(2026, 11, 1)),
                "fromisoformat": staticmethod(__import__("datetime").date.fromisoformat),
            },
        ),
    )
    r = run({R: write({"reviewer": R, "findings": [finding()]})}, exceptions=_exceptions(tmp_path))
    assert r["decision"] == "allow" and r["statuses"][f"{R}/ARC-001"] == {
        "status": "accepted-risk",
        "exception": "EXC-001",
    }


def test_gate_escalates_expired_exception(write, tmp_path, monkeypatch):
    monkeypatch.setattr(
        gate.exc,
        "date",
        type(
            "D",
            (),
            {
                "today": staticmethod(lambda: __import__("datetime").date(2027, 1, 2)),
                "fromisoformat": staticmethod(__import__("datetime").date.fromisoformat),
            },
        ),
    )
    r = run({R: write({"reviewer": R, "findings": [finding()]})}, exceptions=_exceptions(tmp_path))
    assert r["decision"] == "escalate"


def test_gate_escalates_prompt_injection(write, no_exceptions):
    doc = {"reviewer": C, "findings": [finding(C, category="prompt-injection", severity="low", sr_ref="N/A")]}
    assert run({C: write(doc)}, exceptions=no_exceptions)["decision"] == "escalate"


def test_gate_overrides_reviewer_status(write, no_exceptions):
    doc = {"reviewer": R, "findings": [finding(severity="info")]}
    r = run({R: write(doc)}, exceptions=no_exceptions)
    assert r["statuses"][f"{R}/ARC-001"]["status"] == "escalate"  # set by the gate, whatever the reviewer meant


@pytest.mark.parametrize("over", [{"blocking": True}, {"severity": "high"}, {"needs_human": True}])
def test_gate_escalates_new_blocking_finding(write, no_exceptions, over):
    doc = {"reviewer": R, "findings": [finding(**({"sr_ref": "NEW", "severity": "low"} | over))]}
    assert run({R: write(doc)}, exceptions=no_exceptions)["decision"] == "escalate"


def test_gate_escalates_sr_mentioned_in_text_with_new_ref(write, no_exceptions):
    doc = {
        "reviewer": R,
        "findings": [finding(sr_ref="NEW", severity="low", evidence="This violates SR-004: no headers are set.")],
    }
    assert run({R: write(doc)}, exceptions=no_exceptions)["decision"] == "escalate"


def test_gate_new_finding_accept_requires_exception(write, tmp_path):
    p = tmp_path / "e.yml"
    p.write_text(
        yaml.safe_dump(
            [
                {
                    "id": "EXC-002",
                    "sr": ["NEW"],
                    "finding_id": "ARC-001",
                    "paths": ["docs/specs/0001-upload/SPEC-0001.md"],
                    "reason": "Accepted for the demo.",
                    "approved_by": "owner",
                    "approved": "2026-10-27",
                    "expires": "2099-01-01",
                }
            ]
        )
    )
    doc = {"reviewer": R, "findings": [finding(sr_ref="NEW", severity="medium", blocking=True)]}
    assert run({R: write(doc)}, exceptions=str(tmp_path / "none.yml"))["decision"] == "escalate"
    # the entry above is invalid (over 180 days), so it doesn't count either
    assert run({R: write(doc)}, exceptions=str(p))["decision"] == "escalate"


def test_non_security_needs_human_asks_owner(write, no_exceptions):
    doc = {"reviewer": C, "findings": [finding(C, sr_ref="N/A", needs_human=True)]}
    assert run({C: write(doc)}, exceptions=no_exceptions)["decision"] == "questions"


@pytest.mark.parametrize("sev,decision", [("high", "block"), ("medium", "block"), ("low", "allow")])
def test_non_security_findings_go_to_the_author(write, no_exceptions, sev, decision):
    doc = {"reviewer": C, "findings": [finding(C, sr_ref="N/A", severity=sev)]}
    assert run({C: write(doc)}, exceptions=no_exceptions)["decision"] == decision


@pytest.mark.parametrize(
    "doc",
    [
        None,
        "{not json",
        {"reviewer": R},
        {"reviewer": R, "findings": [finding(evidence="too short")]},
        {"reviewer": R, "findings": [finding(sr_ref="whatever")]},
        {"reviewer": R, "findings": [], "allow": True},
        {"reviewer": R, "findings": [finding(evidence="control \x1b[31m characters here")]},
    ],
)
def test_unverifiable_output_escalates_never_allows(write, no_exceptions, doc):
    path = None if doc is None else write(doc)
    assert run({R: path}, exceptions=no_exceptions)["decision"] == "escalate"


def test_output_labelled_as_another_reviewer_escalates(write, no_exceptions):
    doc = {"reviewer": "workflow-iac-reviewer", "findings": []}
    assert run({R: write(doc)}, exceptions=no_exceptions)["decision"] == "escalate"


def test_gate_escalates_on_redaction(write, no_exceptions):
    r = run({R: write({"reviewer": R, "findings": []})}, exceptions=no_exceptions, redactions=1)
    assert r["decision"] == "escalate"


def test_redaction_escalates(write, no_exceptions):
    test_gate_escalates_on_redaction(write, no_exceptions)


def sarif(*levels):
    results = [{"ruleId": f"r{i}", **({"level": lv} if lv else {})} for i, lv in enumerate(levels)]
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": results}]}


def test_sarif_error_blocks(write):
    assert run(sarifs=[write(sarif("error"), "s.sarif")])["decision"] == "block"


def test_sarif_warning_and_default_level_are_notes(write):
    r = run(sarifs=[write(sarif("warning", None, "note"), "s.sarif")])
    assert r["decision"] == "allow" and len(r["notes"]) == 3


@pytest.mark.parametrize("doc", ["{bad", {"version": "2.1.0"}])
def test_invalid_sarif_escalates(write, doc):
    assert run(sarifs=[write(doc, "s.sarif")])["decision"] == "escalate"


def test_exit_codes_and_summary(write, tmp_path, no_exceptions):
    summary = tmp_path / "summary.md"
    ok = write({"reviewer": R, "findings": []})
    assert gate.main(["--reviewer", f"{R}={ok}", "--exceptions", no_exceptions, "--summary", str(summary)]) == 0
    assert gate.main(["--reviewer", f"{R}={tmp_path / 'nope.json'}"]) == 2
    assert "ALLOW" in summary.read_text()


def test_redact_private_key_block():
    from redact import redact

    kind = "OPENSSH " + "PRIVATE KEY"  # built at runtime: no literal key block for scanners
    pem = f"-----BEGIN {kind}-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END {kind}-----"
    out, n = redact(f"found: {pem}")
    assert n == 1 and "b3BlbnNzaC1rZXkt" not in out
    out, n = redact("machine github.com login bot password s3cr3t-value")
    assert n == 1 and "s3cr3t-value" not in out


def test_gate_accepts_valid_new_exception_with_matching_finding_id(write, tmp_path):
    p = tmp_path / "e.yml"
    entry = {
        "id": "EXC-003",
        "sr": ["NEW"],
        "finding_id": "ARC-001",
        "paths": ["docs/specs/0001-upload/SPEC-0001.md"],
        "reason": "Accepted for the demo.",
        "approved_by": "owner",
        "approved": "2026-01-01",
        "expires": "2026-06-30",
    }
    p.write_text(yaml.safe_dump([entry]))
    import datetime

    gate.exc.date = type(
        "D",
        (),
        {
            "today": staticmethod(lambda: datetime.date(2026, 3, 1)),
            "fromisoformat": staticmethod(datetime.date.fromisoformat),
        },
    )
    try:
        doc = {"reviewer": R, "findings": [finding(sr_ref="NEW", severity="medium", blocking=True)]}
        assert run({R: write(doc)}, exceptions=str(p))["decision"] == "allow"
        doc = {"reviewer": R, "findings": [finding(sr_ref="NEW", severity="medium", blocking=True, id="ARC-002")]}
        assert run({R: write(doc)}, exceptions=str(p))["decision"] == "escalate"
    finally:
        gate.exc.date = datetime.date


def test_security_reviewer_na_finding_escalates(write, no_exceptions):
    doc = {"reviewer": R, "findings": [finding(sr_ref="N/A", severity="info")]}
    assert run({R: write(doc)}, exceptions=no_exceptions)["decision"] == "escalate"


def test_gate_never_accepts_high_with_exception(write, tmp_path):
    p = tmp_path / "e.yml"
    entry = {
        "id": "EXC-004",
        "sr": ["SR-015"],
        "paths": ["docs/specs/0001-upload/SPEC-0001.md"],
        "reason": "Accepted for the demo.",
        "approved_by": "owner",
        "approved": "2026-01-01",
        "expires": "2099-01-01",
    }
    p.write_text(yaml.safe_dump([entry]))
    assert gate.classify(R, finding(severity="high"), [entry], "dogs-app") == ("escalate", None)
