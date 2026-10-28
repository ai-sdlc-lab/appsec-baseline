"""SHA-256 over file contents for review reports (SPEC-0001 §2.2, SR-021). Never git's SHA-1 object IDs.

Usage: hash.py REPO_ROOT PATH...   prints {"path": "sha256", ...}
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import InputError, safe_path, sha256_file


def hashes(root: Path, paths: list[str]) -> dict[str, str]:
    out = {}
    for rel in sorted(set(paths)):
        p = safe_path(root, rel)
        if not p.is_file():
            raise InputError(f"not a file: {rel}")
        out[rel] = sha256_file(p)
    return out


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    try:
        print(json.dumps(hashes(Path(sys.argv[1]), sys.argv[2:]), indent=2))
    except InputError as e:
        sys.exit(f"input.rejected: {e}")
