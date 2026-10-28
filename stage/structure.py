"""Template structure check (SPEC-0001 §2.5 step 6).

Every `##` heading of the template must appear in the artifact with non-empty content
(HTML comments and blank lines don't count). A template heading with `<placeholder>` matches
any heading with that prefix, e.g. `## Repo: <name>` needs at least one `## Repo: ...`.
The first heading must start with the artifact's ID (`# INT-0001`).

Usage: structure.py TEMPLATE ARTIFACT
"""

import re
import sys
from pathlib import Path

ID = re.compile(r"^(INT|SPEC|PLAN|TRACE|THREAT)-[0-9]{4}$")
COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def _sections(text: str) -> list[tuple[str, str]]:
    text = COMMENT.sub("", text)
    out, head, body = [], None, []
    for line in text.splitlines():
        if line.startswith("## "):
            if head is not None:
                out.append((head, "\n".join(body)))
            head, body = line[3:].strip(), []
        elif head is not None and not line.startswith("# "):
            body.append(line)
    if head is not None:
        out.append((head, "\n".join(body)))
    return out


def _pattern(heading: str) -> re.Pattern:
    parts = re.split(r"<[^>]+>", heading)
    return re.compile("^" + ".+".join(re.escape(p) for p in parts) + "$")


def check(template: Path, artifact: Path) -> list[str]:
    errs = []
    art_id = artifact.stem
    if not ID.match(art_id):
        return [f"file name is not an artifact ID: {artifact.name}"]
    text = artifact.read_text()
    first = next((ln for ln in text.splitlines() if ln.startswith("# ")), "")
    if not first[2:].startswith(art_id):
        errs.append(f"first heading must start with {art_id}")
    sections = _sections(text)
    for want, _ in _sections(template.read_text()):
        pat = _pattern(want)
        hits = [body for head, body in sections if pat.match(head)]
        if not hits:
            errs.append(f"missing section: {want}")
        elif not any(b.strip() for b in hits):
            errs.append(f"empty section: {want}")
    return errs


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    errs = check(Path(sys.argv[1]), Path(sys.argv[2]))
    for e in errs:
        print(e)
    sys.exit(1 if errs else 0)
