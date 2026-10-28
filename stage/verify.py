"""CI verifier for stage reports (SPEC-0001 §2.5, M-01, M-02, M-18, M-20, M-23). No AI, fail-closed.

Inputs are two checkouts of the product repo (PR head and base), the appsec-baseline checkout this
script runs from (at the lock SHA), and the PR's metadata. Everything read from the head is untrusted.

Usage:
  verify.py --head DIR --base DIR --base-sha SHA --head-sha SHA --repo NAME --head-ref REF
            [--junit FILE] [--lock-on-main identical|behind|other] [--summary FILE] [--comment FILE]
Exit 0 pass, 1 fail. On failure --comment receives an inert PR comment body.
"""

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import crosscheck
import named_tests
import plan_drift
import structure
from classify import changed
from common import STAGE_PREFIX, InputError, change_of, git, load_yaml, safe_path, sha256_file
from render import comment
from validate import check as validate

import exceptions as exc

MARKER = "<!-- appsec-verify -->"
LOCK = re.compile(r"^[0-9a-f]{40}$")
REF_CHANGE = re.compile(r"^(?:stage|feature)/(?P<n>[0-9]{4})-")
WORKFLOW_IAC = re.compile(r"^(\.github/|infra/)")
TEMPLATES = {"INT": "INT.md", "SPEC": "SPEC.md", "PLAN": "PLAN.md", "TRACE": "TRACE.md", "THREAT": "THREAT.md"}


class Result:
    def __init__(self):
        self.failures: list[str] = []
        self.notes: list[str] = []

    def fail(self, msg: str):
        self.failures.append(msg)


def lock_ok(status: str) -> bool:
    """GitHub compare main...<lock>: the lock must be on appsec-baseline main (identical or behind)."""
    return status in ("identical", "behind")


def config(base: Path, head: Path, r: Result):
    """stages.yml and the lock come from the base branch; head only while the base lacks them (M-18)."""
    have = (base / "stages.yml").is_file() and (base / "appsec-baseline.lock").is_file()
    src = base if have else head
    if not have:
        r.notes.append("BOOTSTRAP: base branch has no stages.yml/appsec-baseline.lock, head versions used")
    stages = load_yaml(src / "stages.yml")
    lock = (src / "appsec-baseline.lock").read_text().strip()
    if not LOCK.match(lock):
        raise InputError("appsec-baseline.lock is not a 40-hex commit SHA")
    return stages, lock, not have


def required(stages: dict, kind: str, paths: list[str], change: str | None) -> dict[tuple[str, str], list[str]]:
    """(change, stage) -> reviewers required by this diff."""
    need: dict[tuple[str, str], list[str]] = {}
    for p in paths:
        c = change_of(p)
        if not c:
            continue
        name = p.rsplit("/", 1)[-1]
        for stage, prefix in STAGE_PREFIX.items():
            if stage != "code" and name == f"{prefix}-{c[0]}.md":
                need[(c[0], stage)] = list(stages["stages"][stage]["reviewers"])
    if kind == "code":
        if not change:
            raise InputError("code changes need a change number in the branch name (stage/NNNN-… or feature/NNNN-…)")
        revs = list(stages["stages"]["code"]["reviewers"])
        if any(WORKFLOW_IAC.match(p) for p in paths):
            revs += list(stages["stages"]["code"].get("conditional", {}))
        need[(change, "code")] = revs
    return need


def change_folder(head: Path, n: str) -> Path | None:
    hits = sorted((head / "docs" / "specs").glob(f"{n}-*"))
    return hits[0] if hits else None


def check_report(head: Path, folder: Path, n: str, stage: str, reviewer: str, lock: str, ctx: dict, r: Result):
    rel_folder = folder.relative_to(head).as_posix()
    rp = f"{rel_folder}/reviews/{STAGE_PREFIX[stage]}-{n}.{reviewer}.json"
    try:
        path = safe_path(head, rp)
    except InputError as e:
        return r.fail(str(e))
    if not path.is_file():
        return r.fail(f"missing report {rp}")
    errs = validate("report", path)
    if errs:
        return r.fail(f"{rp}: invalid ({errs[0]})")
    doc = json.loads(path.read_text())
    if (doc["reviewer"], doc["stage"], doc["change"]) != (reviewer, stage, n):
        r.fail(f"{rp}: reviewer/stage/change don't match its file name")
    if doc["appsec_sha"] != lock:
        r.fail(f"{rp}: appsec_sha {doc['appsec_sha'][:12]} is not the lock {lock[:12]}")
    for kind in ("files", "produced"):
        for rel, digest in doc[kind].items():
            try:
                p = safe_path(head, rel)
            except InputError as e:
                r.fail(f"{rp}: {e}")
                continue
            if not p.is_file() or sha256_file(p) != digest:
                r.fail(f"{rp}: {rel} changed after review (hash mismatch)")
    if stage != "code":
        art = f"{rel_folder}/{STAGE_PREFIX[stage]}-{n}.md"
        if art not in doc["files"]:
            r.fail(f"{rp}: the stage artifact {art} is not among the reviewed files")
    else:
        must = [p for p in ctx["paths"] if not p.startswith("docs/") and (head / p).is_file()]
        if reviewer == "workflow-iac-reviewer":
            must = [p for p in must if WORKFLOW_IAC.match(p)]
        for p in must:
            if p not in doc["files"]:
                r.fail(f"{rp}: changed file {p} was not reviewed")
    for f in doc["findings"]:
        if f["status"] == "accepted-risk":
            hit = exc.match(ctx["exceptions"], f, ctx["repo"])
            if hit != f.get("exception"):
                r.fail(f"{rp}: {f['id']} has no valid, unexpired exception")
            else:
                r.notes.append(f"exception used: {hit} for {reviewer} {f['id']} ({f['sr_ref']})")


def run(a) -> Result:
    r = Result()
    head, base = Path(a.head), Path(a.base)
    try:
        stages, lock, bootstrap = config(base, head, r)
        if a.lock_on_main is not None and not lock_ok(a.lock_on_main):
            r.fail(f"lock {lock[:12]} is not on appsec-baseline main ({a.lock_on_main})")
        here = git(ROOT, "rev-parse", "HEAD").decode().strip() if (ROOT / ".git").exists() else lock
        if here != lock:
            r.fail(f"verifier runs at {here[:12]}, lock is {lock[:12]}")
        diff = changed(head, a.base_sha, a.head_sha)
        m = REF_CHANGE.match(a.head_ref or "")
        change = m["n"] if m else None
        need = required(stages, diff["kind"], diff["paths"], change)
    except (InputError, OSError, ValueError, KeyError) as e:
        r.fail(f"input.rejected: {e}")
        return r
    r.notes.append(f"diff: {diff['kind']}, {len(diff['paths'])} path(s)")
    ctx = {
        "paths": diff["paths"],
        "repo": a.repo,
        "exceptions": exc.valid_entries(ROOT / "exceptions" / "sr-exceptions.yml"),
    }

    for (n, stage), reviewers in sorted(need.items()):
        folder = change_folder(head, n)
        if folder is None:
            r.fail(f"change {n}: no folder docs/specs/{n}-*/")
            continue
        for rev in reviewers:
            check_report(head, folder, n, stage, rev, lock, ctx, r)

    template_dirs = [head / ".claude/skills/stage/templates", ROOT / "templates"]
    for p in diff["paths"]:
        m = re.match(r"^docs/specs/[0-9]{4}-[a-z0-9-]+/(INT|SPEC|PLAN|TRACE|THREAT)-[0-9]{4}\.md$", p)
        if not m or not (head / p).is_file():
            continue
        tpl = next((d / TEMPLATES[m.group(1)] for d in template_dirs if (d / TEMPLATES[m.group(1)]).is_file()), None)
        if tpl is None:
            r.fail(f"{p}: no template {TEMPLATES[m.group(1)]}")
            continue
        r.failures += [f"{p}: {e}" for e in structure.check(tpl, head / p)]
        if m.group(1) == "PLAN":
            folder = (head / p).parent
            nn = p.split("/")[2][:4]
            tr, th = folder / f"TRACE-{nn}.md", folder / f"THREAT-{nn}.md"
            if tr.is_file() and th.is_file():
                r.failures += [
                    f"crosscheck: {e}" for e in crosscheck.check(tr.read_text(), th.read_text(), (head / p).read_text())
                ]
            else:
                r.fail(f"{p}: TRACE-/THREAT- files missing for the cross-check")

    if diff["kind"] == "code" and change:
        folder = change_folder(head, change)
        plan_file = folder / f"PLAN-{change}.md" if folder else None
        if not plan_file or not plan_file.is_file():
            r.fail(f"change {change}: PLAN-{change}.md missing")
        else:
            text = plan_file.read_text()
            rel = folder.relative_to(head).as_posix()
            r.failures += [f"plan drift: {e}" for e in plan_drift.check(text, a.repo, rel, diff["paths"])]
            r.failures += [
                f"named tests: {e}" for e in named_tests.check(text, a.repo, Path(a.junit or "/nonexistent"))
            ]
    if bootstrap:
        r.notes.append("BOOTSTRAP mode")
    return r


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    for name in ("--head", "--base", "--base-sha", "--head-sha", "--repo"):
        p.add_argument(name, required=True)
    p.add_argument("--head-ref", default="")
    p.add_argument("--junit")
    p.add_argument("--lock-on-main")
    p.add_argument("--summary")
    p.add_argument("--comment")
    p.add_argument("--today", default=date.today().isoformat())
    a = p.parse_args(argv)
    r = run(a)
    from render import clean

    ok = not r.failures
    lines = [f"## verify: **{'PASS' if ok else 'FAIL'}**", ""]
    lines += [f"- {clean(x)}" for x in r.failures] + [""] + [f"- {clean(x)}" for x in r.notes]
    if a.summary:
        with open(a.summary, "a") as fh:
            fh.write("\n".join(lines) + "\n")
    for x in r.failures:
        print(json.dumps({"event": "verify.fail", "item": clean(x)}))
    print(json.dumps({"event": "verify.pass" if ok else "verify.fail", "failures": len(r.failures)}))
    if a.comment and not ok:
        Path(a.comment).write_text(comment(MARKER, "verify: failed", r.failures))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
