"""Shared helpers for the stage scripts (SPEC-0001 §2.1).

Every path that comes from a report, a diff or a plan is data: it is confined to
the repository root before use, and symlinks are refused. Subprocesses get
argument lists of fixed executables, never a shell string.
"""

import hashlib
import os
import re
import subprocess
from pathlib import Path

import yaml

SECURITY_REVIEWERS = {
    "security-requirements-auditor",
    "security-architect",
    "security-code-reviewer",
    "workflow-iac-reviewer",
    "security-tester",
}
STAGE_PREFIX = {"intent": "INT", "spec": "SPEC", "plan": "PLAN", "code": "CODE"}
CHANGE_DIR = re.compile(r"^docs/specs/(?P<n>[0-9]{4})-(?P<slug>[a-z0-9]+(?:-[a-z0-9]+)*)/")
SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,300}$")


REPO_EXCEPTIONS = "security/exceptions.yml"


def is_doc(path: str) -> bool:
    """Paths that are data, not code: docs/ and the repo's exceptions file (schema-checked by the verifier,
    approved by the owner's merge to main). Everything else is code."""
    return path.startswith("docs/") or path == REPO_EXCEPTIONS


SR_IN_TEXT = re.compile(r"\bSR-[0-9]{3}\b")


def sr_relevant(reviewer: str, f: dict) -> bool:
    """True if this finding concerns a security requirement: it must be fixed, or covered by an exception in the
    repository's own security/exceptions.yml (low/medium only); it can't just be carried. Used by gate and validate.

    A security reviewer must name an SR or NEW: N/A from a security reviewer is treated as owner-decided.
    """
    sr = f.get("sr_ref", "")
    if f.get("category") == "prompt-injection":
        return True
    if sr.startswith("SR-"):
        return True
    if reviewer in SECURITY_REVIEWERS:
        serious = f.get("blocking") or f.get("severity") in ("high", "critical")
        text = f"{f.get('evidence', '')} {f.get('recommendation', '')}"
        return sr != "NEW" or bool(serious or f.get("needs_human") or SR_IN_TEXT.search(text))
    return False


class InputError(ValueError):
    """Untrusted input that the scripts refuse (logged as input.rejected)."""


def safe_path(root: Path, rel: str) -> Path:
    """Resolve a repo-relative path; refuse absolute, `..`, odd characters, symlinks and escapes."""
    if not SAFE_PATH.match(rel) or rel.startswith("/") or ".." in rel.split("/"):
        raise InputError(f"unsafe path: {rel[:80]!r}")
    root = root.resolve()
    p = root / rel
    if p.is_symlink():
        raise InputError(f"symlink refused: {rel}")
    resolved = p.resolve()
    if resolved != root and root not in resolved.parents:
        raise InputError(f"path outside repository: {rel}")
    return p


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_yaml(path: Path):
    with open(path) as fh:
        return yaml.safe_load(fh)


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout


def change_of(path: str):
    """('0001', 'local-stage-loop') for a path inside a change folder, else None."""
    m = CHANGE_DIR.match(path)
    return (m["n"], m["slug"]) if m else None


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)
