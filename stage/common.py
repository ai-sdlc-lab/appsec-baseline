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
