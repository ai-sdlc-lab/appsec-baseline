import json

import pytest

import security_gate as gate

R = "security-architect"


def finding(**over):
    f = {
        "id": "ARC-001",
        "reviewer": R,
        "severity": "medium",
        "sr_ref": "SR-015",
        "file": "docs/specs/upload/spec.md",
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


def run(reviewers=None, sarifs=()):
    return gate.evaluate(reviewers or {}, list(sarifs))


def test_clean_output_allows(write):
    assert run({R: write({"reviewer": R, "findings": []})})["decision"] == "allow"


def test_medium_non_blocking_is_a_note(write):
    r = run({R: write({"reviewer": R, "findings": [finding()]})})
    assert r["decision"] == "allow" and len(r["notes"]) == 1


@pytest.mark.parametrize("over", [{"severity": "high"}, {"severity": "critical"}, {"blocking": True}])
def test_high_or_blocking_blocks(write, over):
    assert run({R: write({"reviewer": R, "findings": [finding(**over)]})})["decision"] == "block"


@pytest.mark.parametrize(
    "doc",
    [
        None,  # missing file
        "{not json",
        {"reviewer": R},  # no findings key
        {"reviewer": R, "findings": [finding(evidence="too short")]},
        {"reviewer": R, "findings": [finding(sr_ref="whatever")]},
        {"reviewer": R, "findings": [], "allow": True},  # extra key smuggled in
    ],
)
def test_unverifiable_output_escalates_never_allows(write, doc):
    path = None if doc is None else write(doc)
    assert run({R: path})["decision"] == "escalate"


def test_output_labelled_as_another_reviewer_escalates(write):
    doc = {"reviewer": "workflow-iac-reviewer", "findings": []}
    assert run({R: write(doc)})["decision"] == "escalate"


def test_prompt_injection_finding_escalates(write):
    doc = {"reviewer": R, "findings": [finding(category="prompt-injection", severity="low")]}
    assert run({R: write(doc)})["decision"] == "escalate"


def test_escalate_wins_over_block(write):
    blocking = write({"reviewer": R, "findings": [finding(severity="high")]}, "a.json")
    r = gate.evaluate({R: blocking, "workflow-iac-reviewer": None}, [])
    assert r["decision"] == "escalate" and r["block"]


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


def test_exit_codes_and_summary(write, tmp_path):
    summary = tmp_path / "summary.md"
    ok = write({"reviewer": R, "findings": []})
    assert gate.main(["--reviewer", f"{R}={ok}", "--summary", str(summary)]) == 0
    assert gate.main(["--reviewer", f"{R}={tmp_path / 'nope.json'}"]) == 2
    assert "ALLOW" in summary.read_text()
