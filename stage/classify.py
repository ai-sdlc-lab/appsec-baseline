"""Changed paths of a PR and its kind: docs or code (SPEC-0001 §2.5 step 4, M-01, M-15). Fail-closed.

Reads `git diff -z --raw -M BASE...HEAD` (NUL-separated, so quoted or odd names can't split).
docs-only iff every path, both sides of renames and deletions included, is under `docs/` or is
`security/exceptions.yml` (common.is_doc),
and no entry is a symlink (120000), a submodule (160000) or a type change. Anything else: code.

Usage: classify.py REPO BASE HEAD   prints {"kind": "docs"|"code", "paths": [...]}
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import git, is_doc

SPECIAL_MODES = {"120000", "160000"}


def parse_raw(raw: bytes) -> list[dict]:
    parts = raw.split(b"\0")
    entries, i = [], 0
    while i < len(parts) and parts[i]:
        meta = parts[i].decode()
        if not meta.startswith(":"):
            raise ValueError("unexpected diff format")
        old_mode, new_mode, _, _, status = meta[1:].split(" ")
        n = 2 if status[0] in "RC" else 1
        paths = [p.decode("utf-8", "surrogateescape") for p in parts[i + 1 : i + 1 + n]]
        entries.append({"status": status[0], "modes": {old_mode, new_mode}, "paths": paths})
        i += 1 + n
    return entries


def classify(entries: list[dict]) -> dict:
    paths = sorted({p for e in entries for p in e["paths"]})
    docs = bool(entries) and all(
        e["status"] != "T" and not (e["modes"] & SPECIAL_MODES) and all(is_doc(p) for p in e["paths"]) for e in entries
    )
    return {"kind": "docs" if docs else "code", "paths": paths}


def changed(repo: Path, base: str, head: str) -> dict:
    return classify(parse_raw(git(repo, "diff", "-z", "--raw", "-M", f"{base}...{head}")))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    print(json.dumps(changed(Path(sys.argv[1]), sys.argv[2], sys.argv[3]), indent=2))
