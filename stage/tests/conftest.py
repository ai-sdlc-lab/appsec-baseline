import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "stage"), str(ROOT / "gate")]


def sh(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True).stdout.strip()


STAGES = {
    "version": 1,
    "max_rounds": 3,
    "stages": {
        "intent": {"reviewers": ["intent-completeness", "security-requirements-auditor"]},
        "spec": {"reviewers": ["spec-completeness", "security-requirements-auditor", "security-architect"]},
        "plan": {"reviewers": ["architecture-conformance", "security-architect"]},
        "code": {
            "reviewers": ["security-code-reviewer"],
            "conditional": {"workflow-iac-reviewer": "^(\\.github/|infra/)"},
        },
    },
}
INT_TEMPLATE = "# INT-<NNNN>: <title>\n\n## Problem\n\n## Out of scope\n"


@pytest.fixture
def repo(tmp_path):
    """A product repo with a base commit (stages.yml, lock, template) and helpers to build a head commit."""
    import yaml

    head = tmp_path / "head"
    head.mkdir()
    sh(head, "init", "-q", "-b", "main")
    sh(head, "config", "user.email", "t@example.org")
    sh(head, "config", "user.name", "t")
    lock = sh(ROOT, "rev-parse", "HEAD")
    (head / "stages.yml").write_text(yaml.safe_dump(STAGES))
    (head / "appsec-baseline.lock").write_text(lock + "\n")
    tpl = head / ".claude/skills/stage/templates"
    tpl.mkdir(parents=True)
    (tpl / "INT.md").write_text(INT_TEMPLATE)
    (head / "api").mkdir()
    (head / "api/main.py").write_text("print('hi')\n")
    sh(head, "add", "-A")
    sh(head, "commit", "-qm", "base")
    base_sha = sh(head, "rev-parse", "HEAD")
    base = tmp_path / "base"
    sh(head, "worktree", "add", "-q", "--detach", str(base), base_sha)

    class R:
        pass

    r = R()
    r.head, r.base, r.base_sha, r.lock, r.tmp = head, base, base_sha, lock, tmp_path

    def commit():
        sh(head, "add", "-A")
        sh(head, "commit", "-qm", "head", "--allow-empty")
        return sh(head, "rev-parse", "HEAD")

    r.commit = commit
    return r


def report(reviewer, stage, change, files, lock, findings=(), produced=None):
    return {
        "reviewer": reviewer,
        "stage": stage,
        "change": change,
        "model": "claude-sonnet-5-5",
        "round": 1,
        "appsec_sha": lock,
        "files": files,
        "produced": produced or {},
        "verdict": "allow",
        "findings": list(findings),
    }


def dump(path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc))
