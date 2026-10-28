"""Write a TRACE-/THREAT- file from a validated reviewer output (SPEC-0001 M-05, M-24).

The main session never writes these files by hand; this script copies the reviewer's
`artifact` field verbatim and prints the file's SHA-256 for the report's `produced` map.

Usage: write_artifact.py OUTPUT.json REPO_ROOT DEST_REL_PATH
"""

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from common import InputError, safe_path, sha256_file
from validate import check

sys.path.insert(0, str(HERE.parent / "gate"))
from redact import redact

DEST = re.compile(r"^docs/specs/[0-9]{4}-[a-z0-9-]+/(TRACE|THREAT)-[0-9]{4}\.md$")


def write(output: Path, root: Path, dest: str) -> str:
    if not DEST.match(dest):
        raise InputError(f"destination must be a TRACE-/THREAT- file in a change folder: {dest}")
    errs = check("output", output)
    if errs:
        raise InputError("reviewer output invalid: " + "; ".join(errs))
    art = json.loads(output.read_text()).get("artifact")
    if not art:
        raise InputError("reviewer output has no artifact")
    if redact(art)[1]:
        raise InputError("credential-like string in the artifact: escalate to the owner, nothing written")
    p = safe_path(root, dest)
    p.write_text(art if art.endswith("\n") else art + "\n")
    return sha256_file(p)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    try:
        print(write(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]))
    except InputError as e:
        sys.exit(f"input.rejected: {e}")
