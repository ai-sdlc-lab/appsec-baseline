import argparse

import pytest
import verify
from common import sha256_file
from conftest import dump, report, sh

CH = "docs/specs/0001-demo"
INT = f"{CH}/INT-0001.md"
INT_TEXT = "# INT-0001: demo\n\n## Problem\nSomething.\n\n## Out of scope\nNothing.\n"


def args(r, head_sha, ref="stage/0001-intent", junit=None, onmain="identical", base_ref="feature/0001-demo"):
    return argparse.Namespace(
        head=str(r.head),
        base=str(r.base),
        base_sha=r.base_sha,
        head_sha=head_sha,
        repo="dogs-app",
        head_ref=ref,
        base_ref=base_ref,
        junit=junit,
        lock_on_main=onmain,
    )


def intent_change(r, edit_after=False, skip=None, findings=None, verdict="allow"):
    (r.head / INT).parent.mkdir(parents=True, exist_ok=True)
    (r.head / INT).write_text(INT_TEXT)
    digest = sha256_file(r.head / INT)
    for rev in ("intent-completeness", "security-requirements-auditor"):
        if rev == skip:
            continue
        dump(
            r.head / f"{CH}/reviews/INT-0001.{rev}.json",
            report(rev, "intent", "0001", {INT: digest}, r.lock, findings or [], verdict=verdict),
        )
    if edit_after:
        (r.head / INT).write_text(INT_TEXT + "edited\n")
    return r.commit()


def test_verify_passes_clean_intent(repo):
    res = verify.run(args(repo, intent_change(repo)))
    assert res.failures == []


def test_verify_fails_on_stale_report(repo):
    res = verify.run(args(repo, intent_change(repo, edit_after=True)))
    assert any("changed after review" in f for f in res.failures)


def test_verify_fails_on_missing_reviewer_report(repo):
    res = verify.run(args(repo, intent_change(repo, skip="security-requirements-auditor")))
    assert any("missing report" in f for f in res.failures)


def test_verify_reads_stages_from_base_not_head(repo):
    import yaml

    stages = yaml.safe_load((repo.head / "stages.yml").read_text())
    stages["stages"]["intent"]["reviewers"] = ["intent-completeness"]  # PR drops a reviewer
    (repo.head / "stages.yml").write_text(yaml.safe_dump(stages))
    res = verify.run(args(repo, intent_change(repo, skip="security-requirements-auditor")))
    assert any("security-requirements-auditor" in f for f in res.failures)


@pytest.mark.parametrize("status", ["ahead", "diverged", "error", ""])
def test_verify_rejects_lock_not_on_appsec_main(repo, status):
    res = verify.run(args(repo, intent_change(repo), onmain=status))
    assert any("not on appsec-baseline main" in f for f in res.failures)


def test_verify_fails_code_pr_without_stage_folder(repo):
    (repo.head / "api/main.py").write_text("print('changed')\n")
    res = verify.run(args(repo, repo.commit(), ref="stage/0001-code"))
    assert any("no folder" in f or "missing report" in f for f in res.failures)


def code_change(r, reviewed, extra_files=()):
    (r.head / "api/main.py").write_text("print('changed')\n")
    for p in extra_files:
        (r.head / p).parent.mkdir(parents=True, exist_ok=True)
        (r.head / p).write_text("x: 1\n")
    (r.head / INT).parent.mkdir(parents=True, exist_ok=True)
    (r.head / f"{CH}/PLAN-0001.md").write_text(
        "# PLAN-0001\n\n## Repo: dogs-app\n| # | Files | Implements | Tests |\n|---|---|---|---|\n| D-01 | `api/main.py` | SR-001 | `test_x` |\n"
    )
    files = {p: sha256_file(r.head / p) for p in reviewed}
    dump(
        r.head / f"{CH}/reviews/CODE-0001.security-code-reviewer.json",
        report("security-code-reviewer", "code", "0001", files, r.lock),
    )
    return r.commit()


def test_verify_fails_on_changed_file_missing_from_report(repo):
    res = verify.run(args(repo, code_change(repo, reviewed=[f"{CH}/PLAN-0001.md"]), ref="stage/0001-code"))
    assert any("api/main.py was not reviewed" in f for f in res.failures)


def test_verify_requires_workflow_iac_report_when_github_changed(repo):
    sha = code_change(repo, reviewed=["api/main.py"], extra_files=[".github/workflows/x.yml"])
    res = verify.run(args(repo, sha, ref="stage/0001-code"))
    assert any("CODE-0001.workflow-iac-reviewer.json" in f for f in res.failures)


def sr_finding(status, **over):
    f = {
        "id": "AUD-001",
        "severity": "low",
        "sr_ref": "SR-004",
        "file": INT,
        "line": 1,
        "evidence": "Headers are not mentioned anywhere in the intent.",
        "status": status,
    }
    return f | over


@pytest.mark.parametrize("status", ["carried"])
def test_verify_rejects_sr_finding_with_status_carried_or_fixed(repo, status):
    res = verify.run(args(repo, intent_change(repo, findings=[sr_finding(status)])))
    assert any("invalid" in f for f in res.failures)


def test_verify_rejects_carried_blocking_or_high(repo):
    f = sr_finding("carried", sr_ref="N/A", severity="high")
    res = verify.run(args(repo, intent_change(repo, findings=[f])))
    assert any("invalid" in x for x in res.failures)


def test_verify_bootstrap_only_when_base_lacks_files(repo):
    sh(repo.head, "rm", "-q", "stages.yml", "appsec-baseline.lock")
    sh(repo.head, "commit", "-qm", "base without config")
    repo.base_sha = sh(repo.head, "rev-parse", "HEAD")
    sh(repo.base, "checkout", "-q", "--detach", repo.base_sha)
    import yaml
    from conftest import STAGES

    (repo.head / "stages.yml").write_text(yaml.safe_dump(STAGES))
    (repo.head / "appsec-baseline.lock").write_text(repo.lock + "\n")
    res = verify.run(args(repo, intent_change(repo)))
    # adding stages.yml and the lock is a code change, so a code-stage report is rightly required
    assert any("BOOTSTRAP" in n for n in res.notes)
    assert not any("input.rejected" in f for f in res.failures)


def test_verify_does_not_fall_back_when_base_has_files(repo):
    res = verify.run(args(repo, intent_change(repo)))
    assert not any("BOOTSTRAP" in n for n in res.notes)


def _repo_exceptions(r, **over):
    from datetime import date, timedelta

    import yaml

    today = date.today()
    e = {
        "id": "EXC-009",
        "sr": ["SR-004"],
        "paths": [INT],
        "reason": "Not fixable in three rounds; tracked for the next change.",
        "approved_by": "agent",
        "approved": today.isoformat(),
        "expires": (today + timedelta(days=30)).isoformat(),
    } | over
    (r.head / "security").mkdir(exist_ok=True)
    (r.head / "security/exceptions.yml").write_text(yaml.safe_dump([e]))


def test_verify_uses_the_repos_own_exceptions(repo):
    _repo_exceptions(repo)
    f = sr_finding("accepted-risk", exception="EXC-009")
    res = verify.run(args(repo, intent_change(repo, findings=[f])))
    assert res.failures == [] and any("exception used: EXC-009" in n for n in res.notes)
    assert any("EXC-009 SR-004 by agent" in n for n in res.notes)


def test_verify_rejects_agent_exception_over_90_days(repo):
    from datetime import date, timedelta

    _repo_exceptions(repo, expires=(date.today() + timedelta(days=120)).isoformat())
    res = verify.run(args(repo, intent_change(repo, findings=[sr_finding("accepted-risk", exception="EXC-009")])))
    assert any("security/exceptions.yml: EXC-009" in f and "90 days" in f for f in res.failures)


def test_verify_rejects_accepted_high_finding(repo):
    _repo_exceptions(repo)
    f = sr_finding("accepted-risk", exception="EXC-009", severity="high")
    res = verify.run(args(repo, intent_change(repo, findings=[f])))
    assert any("invalid" in x for x in res.failures)


def test_verify_open_finding_blocks_only_the_merge_to_main(repo):
    f = sr_finding("open", severity="high")
    sha = intent_change(repo, findings=[f], verdict="open")
    into_feature = verify.run(args(repo, sha))
    assert into_feature.failures == [] and any("is open" in n for n in into_feature.notes)
    into_main = verify.run(args(repo, sha, ref="feature/0001-demo", base_ref="main"))
    assert any("is open" in x and "owner decides" in x for x in into_main.failures)


def test_verify_fails_on_edited_threat_file(repo):
    spec = f"{CH}/SPEC-0001.md"
    threat = f"{CH}/THREAT-0001.md"
    (repo.head / spec).parent.mkdir(parents=True, exist_ok=True)
    (repo.head / spec).write_text("# SPEC-0001\n")
    (repo.head / threat).write_text("# THREAT-0001: threat model\n")
    produced = {threat: sha256_file(repo.head / threat)}
    (repo.head / threat).write_text("# THREAT-0001: threat model (softened by hand)\n")
    dump(
        repo.head / f"{CH}/reviews/SPEC-0001.security-architect.json",
        report(
            "security-architect", "spec", "0001", {spec: sha256_file(repo.head / spec)}, repo.lock, produced=produced
        ),
    )
    res = verify.run(args(repo, repo.commit(), ref="stage/0001-spec"))
    assert any(f"{threat} changed after review" in f for f in res.failures)


def _spec_change(r, produced_for_architect=True, edit_threat_only=False):
    spec, trace, threat = f"{CH}/SPEC-0001.md", f"{CH}/TRACE-0001.md", f"{CH}/THREAT-0001.md"
    (r.head / spec).parent.mkdir(parents=True, exist_ok=True)
    for p, t in ((spec, "# SPEC-0001\n"), (trace, "# TRACE-0001\n"), (threat, "# THREAT-0001\n")):
        (r.head / p).write_text(t)
    files = {spec: sha256_file(r.head / spec)}
    for rev, prod in (
        ("spec-completeness", {}),
        ("security-requirements-auditor", {trace: sha256_file(r.head / trace)}),
        ("security-architect", {threat: sha256_file(r.head / threat)} if produced_for_architect else {}),
    ):
        dump(r.head / f"{CH}/reviews/SPEC-0001.{rev}.json", report(rev, "spec", "0001", files, r.lock, produced=prod))
    sha = r.commit()
    if edit_threat_only:
        (r.head / threat).write_text("# THREAT-0001 (edited later, alone)\n")
        r.base_sha = sha
        sh(r.base, "checkout", "-q", "--detach", sha)
        sha = r.commit()
    return sha


def test_verify_requires_produced_threat_and_trace(repo):
    res = verify.run(args(repo, _spec_change(repo, produced_for_architect=False), ref="stage/0001-spec"))
    assert any("THREAT-0001.md must be listed in produced" in f for f in res.failures)


def test_verify_checks_reports_when_only_threat_changes(repo):
    res = verify.run(args(repo, _spec_change(repo, edit_threat_only=True), ref="stage/0001-spec"))
    assert any("THREAT-0001.md changed after review" in f for f in res.failures)


def test_verify_uses_base_templates_not_head(repo):
    # the PR empties its own copy of the template; the base template still applies
    (repo.head / ".claude/skills/stage/templates/INT.md").write_text("# INT-<NNNN>\n")
    (repo.head / INT).parent.mkdir(parents=True, exist_ok=True)
    (repo.head / INT).write_text("# INT-0001: demo\n")
    for rev in ("intent-completeness", "security-requirements-auditor"):
        dump(
            repo.head / f"{CH}/reviews/INT-0001.{rev}.json",
            report(rev, "intent", "0001", {INT: sha256_file(repo.head / INT)}, repo.lock),
        )
    res = verify.run(args(repo, repo.commit(), ref="stage/0001-intent"))
    assert any("missing section: Problem" in f for f in res.failures)


def test_verify_rejects_finding_on_unreviewed_file(repo):
    f = {
        "id": "IC-001",
        "severity": "low",
        "sr_ref": "N/A",
        "file": "api/main.py",
        "line": 1,
        "evidence": "x" * 30,
        "status": "carried",
    }
    res = verify.run(args(repo, intent_change(repo, findings=[f])))
    assert any("didn't review" in x for x in res.failures)


PATH_SCOPED = {
    "reviewers": [],
    "conditional": {
        "security-code-reviewer": "^(?!\\.github/|infra/)",
        "workflow-iac-reviewer": "^(\\.github/|infra/)",
    },
}


def path_scoped(r):
    import yaml

    s = yaml.safe_load((r.base / "stages.yml").read_text())
    s["stages"]["code"] = PATH_SCOPED
    (r.base / "stages.yml").write_text(yaml.safe_dump(s))


def test_verify_workflow_only_change_needs_no_code_reviewer(repo):
    path_scoped(repo)
    (repo.head / ".github/workflows").mkdir(parents=True)
    (repo.head / ".github/workflows/x.yml").write_text("x: 1\n")
    (repo.head / f"{CH}/reviews").mkdir(parents=True)
    (repo.head / f"{CH}/PLAN-0001.md").write_text("# PLAN-0001\n")
    sha = repo.commit()
    need = verify.required(
        verify.load_yaml(repo.base / "stages.yml"),
        "code",
        [".github/workflows/x.yml", f"{CH}/PLAN-0001.md"],
        "0001",
    )
    assert need[("0001", "code")] == ["workflow-iac-reviewer"]
    res = verify.run(args(repo, sha, ref="stage/0001-code"))
    assert not any("security-code-reviewer" in f for f in res.failures)


def test_verify_path_scoped_reviewer_must_cover_its_files(repo):
    path_scoped(repo)
    res = verify.run(
        args(
            repo,
            code_change(repo, reviewed=[f"{CH}/PLAN-0001.md"]),
            ref="stage/0001-code",
        )
    )
    assert any("api/main.py was not reviewed" in f for f in res.failures)
    assert not any("workflow-iac-reviewer" in f for f in res.failures)
