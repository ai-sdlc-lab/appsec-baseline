import json
import os
import re
import shutil
import subprocess
from datetime import date
from pathlib import Path

import crosscheck
import named_tests
import plan_drift
import pytest
import structure
import validate
import write_artifact
from classify import classify, parse_raw
from common import InputError
from conftest import ROOT, report
from hash import hashes
from log import REQUIRED, event
from render import clean, comment

import exceptions as exc

LOCK = "a" * 40


# --- schemas (A-01) ---------------------------------------------------------------------------


def _report_file(tmp_path, doc):
    p = tmp_path / "r.json"
    p.write_text(doc if isinstance(doc, str) else json.dumps(doc))
    return p


def test_report_schema_rejects_unknown_fields_and_oversize(tmp_path):
    ok = report("intent-completeness", "intent", "0001", {"docs/a.md": "0" * 64}, LOCK)
    assert validate.check("report", _report_file(tmp_path, ok)) == []
    assert validate.check("report", _report_file(tmp_path, ok | {"allow": True}))
    big = ok | {"findings": []}
    assert validate.check("report", _report_file(tmp_path, json.dumps(big) + " " * (256 * 1024)))


@pytest.mark.parametrize(
    "files",
    [{"../etc/passwd": "0" * 64}, {"/abs/path": "0" * 64}, {"a b.md": "0" * 64}, {"docs/a.md": "nothex"}],
)
def test_report_schema_rejects_bad_paths_control_chars_and_long_strings(tmp_path, files):
    doc = report("intent-completeness", "intent", "0001", files, LOCK)
    assert validate.check("report", _report_file(tmp_path, doc))
    f = {"id": "IC-001", "severity": "low", "sr_ref": "N/A", "file": "docs/a.md", "line": 1, "status": "carried"}
    for evidence in ("bad\x1b[31m control", "x" * 2001):
        doc = report(
            "intent-completeness", "intent", "0001", {"docs/a.md": "0" * 64}, LOCK, [f | {"evidence": evidence}]
        )
        assert validate.check("report", _report_file(tmp_path, doc))


def test_review_schema_reviewer_enum_matches_stages_yml():
    from conftest import STAGES

    enum = set(json.loads((ROOT / "schemas/review-report.schema.json").read_text())["properties"]["reviewer"]["enum"])
    used = {r for s in STAGES["stages"].values() for r in s["reviewers"]} | set(STAGES["stages"]["code"]["conditional"])
    assert enum == used


def test_verifier_requirements_have_hashes():
    lines = [ln for ln in (ROOT / "gate/requirements.txt").read_text().splitlines() if "==" in ln]
    text = (ROOT / "gate/requirements.txt").read_text()
    assert lines and text.count("--hash=sha256:") >= len(lines)


# --- hash / write_artifact (A-02) -------------------------------------------------------------


def test_hash_rejects_path_outside_repo_and_symlink(tmp_path):
    (tmp_path / "ok.md").write_text("x")
    (tmp_path / "link.md").symlink_to(tmp_path / "ok.md")
    assert set(hashes(tmp_path, ["ok.md"])) == {"ok.md"}
    for bad in ("../x", "/etc/passwd", "link.md", "a/../../x"):
        with pytest.raises(InputError):
            hashes(tmp_path, [bad])


def test_write_artifact_only_to_trace_threat(tmp_path):
    out = tmp_path / "o.json"
    out.write_text(json.dumps({"reviewer": "security-architect", "artifact": "# THREAT-0001\n", "findings": []}))
    (tmp_path / "docs/specs/0001-x").mkdir(parents=True)
    assert len(write_artifact.write(out, tmp_path, "docs/specs/0001-x/THREAT-0001.md")) == 64
    with pytest.raises(InputError):
        write_artifact.write(out, tmp_path, "docs/specs/0001-x/SPEC-0001.md")


# --- exceptions (A-04) --------------------------------------------------------------------------


def _exc_file(tmp_path, **over):
    e = {
        "id": "EXC-001",
        "sr": ["SR-002"],
        "repo": "dogs-app",
        "paths": [".github/workflows/deploy.yml"],
        "reason": "A documented lab reason.",
        "approved_by": "owner",
        "approved": "2026-10-27",
        "expires": "2026-12-31",
    } | over
    p = tmp_path / "e.yml"
    import yaml

    p.write_text(yaml.safe_dump([e]))
    return p


def test_exceptions_reject_over_180_days(tmp_path):
    assert exc.errors(_exc_file(tmp_path, expires="2027-06-30"))


def test_exceptions_reject_missing_expiry(tmp_path):
    import yaml

    p = _exc_file(tmp_path)
    data = yaml.safe_load(p.read_text())
    del data[0]["expires"]
    p.write_text(yaml.safe_dump(data))
    assert exc.errors(p)


@pytest.mark.parametrize("path", ["*", "**", "**/x.yml"])
def test_exceptions_reject_catch_all_glob(tmp_path, path):
    assert exc.errors(_exc_file(tmp_path, paths=[path]))


@pytest.mark.parametrize("path", ["*.yml", "*/deploy.yml"])
def test_exceptions_reject_top_level_wildcards(tmp_path, path):
    assert exc.errors(_exc_file(tmp_path, paths=[path]))


def test_gate_ignores_malformed_exception(tmp_path):
    assert exc.valid_entries(_exc_file(tmp_path, sr=[]), today=date(2026, 11, 1)) == []
    assert exc.valid_entries(_exc_file(tmp_path), today=date(2027, 1, 1)) == []  # expired
    assert len(exc.valid_entries(_exc_file(tmp_path), today=date(2026, 11, 1))) == 1


def test_exc001_scoped_to_deploy_yml_and_expires():
    entries = [e for e in exc.load() if e["id"] == "EXC-001"]
    assert exc.errors() == []
    assert entries[0]["paths"] == [".github/workflows/deploy.yml"] and entries[0]["expires"] == "2026-12-31"


# --- structure / crosscheck / plan drift / named tests (A-05) ------------------------------


def test_structure_fails_on_empty_section(tmp_path):
    tpl = tmp_path / "INT.md"
    tpl.write_text("# INT-<NNNN>\n\n## Problem\n<!-- hint -->\n\n## Out of scope\n")
    art = tmp_path / "INT-0001.md"
    art.write_text("# INT-0001: x\n\n## Problem\n<!-- only a comment -->\n\n## Out of scope\nNone.\n")
    assert structure.check(tpl, art) == ["empty section: Problem"]
    art.write_text("# INT-0001: x\n\n## Problem\nReal.\n\n## Out of scope\nNone.\n")
    assert structure.check(tpl, art) == []


PLAN = """# PLAN-0001
## Repo: dogs-app
| # | Files | Implements | Tests |
|---|---|---|---|
| D-01 | `api/app/*.py`, `tests/process/**` | SR-001; M-01 | `test_a`, `test_b` |
| D-02 | `docs/x.md` | M-02 | manual |
"""
TRACE = "| SR-001 | MUST | covered | x | y |\n| SR-004 | MUST | N/A | - | - |\n"
THREAT = (
    "## Required mitigations\n| ID | M | SR | Step |\n|---|---|---|---|\n| M-01 | x | y | z |\n| M-02 | x | y | z |\n"
)


def test_crosscheck_fails_on_sr_without_task_and_test():
    assert crosscheck.check(
        TRACE + "| SR-031 | MUST | covered | x | y |\n", THREAT.replace("| M-02 | x | y | z |\n", ""), PLAN
    ) == ["SR-031: no plan step with a named test"]


def test_crosscheck_fails_on_threat_mitigation_without_task_and_test():
    assert crosscheck.check(TRACE, THREAT, PLAN) == ["M-02: no plan step with a named test"]


def test_plan_drift_fails_on_unlisted_file():
    paths = ["api/app/main.py", "tests/process/sub/test_x.py", "docs/specs/0001-x/reviews/r.json", "Makefile"]
    assert plan_drift.check(PLAN, "dogs-app", "docs/specs/0001-x", paths) == [
        "Makefile: not listed in the dogs-app section of the plan"
    ]


def _junit(tmp_path, body):
    p = tmp_path / "junit.xml"
    p.write_text(f"<testsuites><testsuite>{body}</testsuite></testsuites>")
    return p


def test_named_tests_fails_on_missing_test(tmp_path):
    assert named_tests.check(PLAN, "dogs-app", _junit(tmp_path, '<testcase name="test_a"/>')) == [
        "test_b: not found or skipped in the test run"
    ]


def test_named_tests_fails_when_junit_missing(tmp_path):
    assert named_tests.check(PLAN, "dogs-app", tmp_path / "none.xml") == ["JUnit report missing"]


def test_named_tests_fails_on_failed_test(tmp_path):
    body = '<testcase name="test_a"/><testcase name="test_b[x]"><failure/></testcase><testcase name="test_b[y]"/>'
    assert named_tests.check(PLAN, "dogs-app", _junit(tmp_path, body)) == ["test_b: failed"]


def test_named_tests_rejects_doctype_and_oversize_junit(tmp_path):
    p = tmp_path / "j.xml"
    p.write_text('<!DOCTYPE x [<!ENTITY a "aaaa">]><testsuites/>')
    assert "DOCTYPE" in named_tests.check(PLAN, "dogs-app", p)[0]
    p.write_bytes(b"<testsuites>" + b" " * (5 * 1024 * 1024) + b"</testsuites>")
    assert "5 MiB" in named_tests.check(PLAN, "dogs-app", p)[0]


def _raw(*entries):
    return b"".join(
        f":{a} {b} 0 0 {s}\0".encode() + b"\0".join(p.encode() for p in ps) + b"\0" for a, b, s, ps in entries
    )


def test_classify_docs_only():
    assert classify(parse_raw(_raw(("100644", "100644", "M", ["docs/a.md"]))))["kind"] == "docs"


def test_classify_rename_out_of_api_is_code():
    assert classify(parse_raw(_raw(("100644", "100644", "R100", ["api/x.py", "docs/x.py"]))))["kind"] == "code"


def test_classify_symlink_is_code():
    assert classify(parse_raw(_raw(("000000", "120000", "A", ["docs/link"]))))["kind"] == "code"


def test_classify_handles_nul_and_quoted_paths():
    r = classify(parse_raw(_raw(("100644", "100644", "M", ['docs/we"ird\nname.md']))))
    assert r == {"kind": "docs", "paths": ['docs/we"ird\nname.md']}


def test_classify_submodule_and_typechange_is_code():
    assert classify(parse_raw(_raw(("000000", "160000", "A", ["docs/sub"]))))["kind"] == "code"
    assert classify(parse_raw(_raw(("100644", "120000", "T", ["docs/a"]))))["kind"] == "code"


# --- log / render (A-06) ----------------------------------------------------------------------


def test_log_events_have_required_fields_and_no_secrets(capsys):
    rec = event(
        "authz.denied",
        "denied",
        service="hook",
        version=LOCK,
        actor="author",
        request_id="s1",
        change="0001",
        stage="code",
        reason="outside_scope",
        path="x\n::stop",
    )
    line = capsys.readouterr().out.strip()
    assert all(k in rec for k in REQUIRED) and rec["ts"].endswith("Z") and "\n" not in line
    with pytest.raises(ValueError):
        event("made.up", "success", service="x", version="v", actor="a", request_id="r")


def test_comment_renders_untrusted_text_inert():
    body = comment("<!-- m -->", "t", ["`code` @owner [x](https://evil) ![i](https://e/i.png)", "e" * 10000])
    assert "@owner" not in body and "](" not in body and "https://" not in body and "`code`" not in body
    assert max(len(ln) for ln in body.splitlines()) <= 210


def test_comment_escapes_markup_and_mentions():
    assert clean("<script>@team") == "‹script›@\u200bteam"


def test_logs_neutralise_workflow_commands():
    assert not clean("::add-mask::secret").startswith("::")


def test_logs_neutralise_embedded_newlines():
    assert "\n" not in clean("ok\n::error::forged") and "\r" not in clean("a\rb")


# --- workflows (A-08, A-09, A-10) -------------------------------------------------------------


def _wf(name):
    import yaml

    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def test_verify_job_permissions_minimal():
    wf = _wf("verify.yml")
    assert wf["permissions"] == {}
    job = wf["jobs"]["verify"]
    assert job["permissions"] == {"contents": "read", "pull-requests": "write"} and job["timeout-minutes"] <= 30
    for step in job["steps"]:
        if "uses" in step:
            assert "@" in step["uses"] and len(step["uses"].split("@")[1].split()[0]) == 40
            if step["uses"].startswith("actions/checkout"):
                assert step["with"]["persist-credentials"] is False


def test_verify_job_runs_no_pr_code():
    text = (ROOT / ".github/workflows/verify.yml").read_text()
    runs = [s.get("run", "") for s in _wf("verify.yml")["jobs"]["verify"]["steps"]]
    for run in runs:
        for line in run.splitlines():
            assert not re.search(r"(python|bash|sh|make|npm|node|pytest)\s+(-\S+\s+)*(\./)?head/", line), line
            if "pip install" in line:
                assert ".appsec/gate/requirements.txt" in line and "--require-hashes" in line
    assert "${{ github.head_ref }}" not in "".join(runs) and "pull_request_target" not in text


def test_comment_only_on_failure_and_deleted_when_clean():
    step = next(
        s for s in _wf("verify.yml")["jobs"]["verify"]["steps"] if s.get("name", "").startswith("Failure comment")
    )
    assert 'if [[ -f "$RUNNER_TEMP/comment.md" ]]' in step["run"] and "-X DELETE" in step["run"]


def test_comment_cleanup_ignores_foreign_comments():
    for wf, job in (("verify.yml", "verify"), ("security-review.yml", "review")):
        steps = _wf(wf)["jobs"][job]["steps"]
        runs = " ".join(s.get("run", "") for s in steps)
        assert "github-actions[bot]" in runs


def _review_step():
    return next(
        s
        for s in _wf("security-review.yml")["jobs"]["review"]["steps"]
        if "only if there are findings" in s.get("name", "")
    )


def test_security_review_no_comment_on_allow():
    run = _review_step()["run"]
    assert 'if [[ "$n" == 0 ]]' in run and "exit 0" in run


def test_security_review_no_comment_without_findings():
    run = _review_step()["run"]
    # an API error leaves no review.json: jq fails -> n=0 -> no comment, earlier comment deleted
    assert "|| echo 0" in run and "-X DELETE" in run and ".artifact" not in run


def test_semgrep_tls_rule_flags_insecure():
    if not shutil.which("semgrep"):
        pytest.skip("semgrep not installed here; the scanners job runs semgrep --test")
    r = subprocess.run(
        ["semgrep", "--test", str(ROOT / "semgrep")], check=False, capture_output=True, text=True, env=os.environ
    )
    assert r.returncode == 0, r.stdout + r.stderr


# --- agents (A-11) --------------------------------------------------------------------------------

SPEC_TABLE = {
    "security-requirements-auditor": ("claude-sonnet-5-5", 30),
    "security-architect": ("claude-sonnet-5-5", 30),
    "security-code-reviewer": ("claude-sonnet-5-5", 40),
    "workflow-iac-reviewer": ("claude-sonnet-5-5", 30),
}


def _front(path: Path) -> dict:
    import yaml

    return yaml.safe_load(path.read_text().split("---")[1])


def test_agents_have_no_shell_or_network_tools():
    for p in (ROOT / "agents").glob("*.md"):
        tools = {t.strip() for t in _front(p)["tools"].split(",")}
        assert tools <= {"Read", "Grep", "Glob", "StructuredOutput"}, p.name


def test_agents_match_spec_table():
    for name, (model, turns) in SPEC_TABLE.items():
        fm = _front(ROOT / "agents" / f"{name}.md")
        assert (fm["model"], fm["maxTurns"]) == (model, turns), name
        assert "Untrusted input rule" in (ROOT / "agents" / f"{name}.md").read_text()


def test_named_tests_rejects_utf16_doctype(tmp_path):
    p = tmp_path / "j.xml"
    p.write_bytes('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE a [<!ENTITY e "v">]><testsuites/>'.encode("utf-16"))
    assert named_tests.check(PLAN, "dogs-app", p)


def test_report_rejects_owner_decided_finding_as_carried(tmp_path):
    f = {
        "id": "AUD-001",
        "severity": "low",
        "sr_ref": "NEW",
        "file": "docs/a.md",
        "line": 1,
        "status": "carried",
        "evidence": "This conflicts with SR-020 authorisation.",
    }
    doc = report("security-requirements-auditor", "intent", "0001", {"docs/a.md": "0" * 64}, LOCK, [f])
    assert any("owner decides" in e for e in validate.check("report", _report_file(tmp_path, doc)))
    doc["findings"][0] |= {"sr_ref": "N/A", "evidence": "plain evidence text here"}
    assert any("must reference an SR" in e for e in validate.check("report", _report_file(tmp_path, doc)))


def test_write_artifact_refuses_credentials(tmp_path):
    out = tmp_path / "o.json"
    out.write_text(
        json.dumps(
            {
                "reviewer": "security-architect",
                "artifact": "# THREAT-0001\nkey " + "AKIA" + "ABCDEFGHIJKLMNOP" + "\n",
                "findings": [],
            }
        )
    )
    (tmp_path / "docs/specs/0001-x").mkdir(parents=True)
    with pytest.raises(InputError):
        write_artifact.write(out, tmp_path, "docs/specs/0001-x/THREAT-0001.md")


def test_crosscheck_fails_closed_on_format_drift():
    assert crosscheck.check(TRACE, "## Mitigations\n| M-01 | x |\n", PLAN)
    assert crosscheck.check("| SR-001 | MUST | Covered | x |\n", THREAT, PLAN)


def test_plan_drift_rejects_catch_all_entries():
    plan = PLAN.replace("`docs/x.md`", "`**/*`")
    assert "catch-all" in plan_drift.check(plan, "dogs-app", "docs/specs/0001-x", ["Makefile"])[0]


def test_exceptions_not_valid_before_approved(tmp_path):
    assert (
        exc.valid_entries(_exc_file(tmp_path, approved="2026-12-01", expires="2026-12-31"), today=date(2026, 11, 1))
        == []
    )


def test_redact_is_linear_on_whitespace():
    import time

    from redact import redact

    t = time.monotonic()
    redact("\n" * 200000 + " " * 200000)
    assert time.monotonic() - t < 2


def test_named_tests_rejects_bomless_utf16_doctype(tmp_path):
    p = tmp_path / "j.xml"
    p.write_bytes(
        '<!DOCTYPE a [<!ENTITY x "y">]><testsuites><testsuite><testcase name="test_a"/></testsuite></testsuites>'.encode(
            "utf-16-le"
        )
    )
    assert named_tests.check(PLAN, "dogs-app", p)


def test_workflow_python_runs_isolated():
    """PR files in the workspace root must never shadow stdlib or pip (IAC-005)."""
    for name in ("security-review.yml", "verify.yml"):
        text = (ROOT / ".github/workflows" / name).read_text()
        for line in text.splitlines():
            m = re.search(r"\bpython3?\s+(\S+)", line)
            if m and not line.strip().startswith("#") and "setup-python" not in line:
                assert m.group(1) == "-I", f"{name}: {line.strip()}"
