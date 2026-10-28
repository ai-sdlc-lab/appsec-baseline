"""JSON Lines events for hook, gate, loop and verifier (SPEC-0001 §7).

Fields: ts, level, service, version, event, outcome, reason, actor, change, stage, request_id,
plus event-specific fields. Values pass through render.clean, so a value can't forge a new
log line or a workflow command. Never pass tokens, headers, bodies or file contents here.
"""

import json
import sys
from datetime import UTC, datetime

from render import clean

EVENTS = {
    "stage.start",
    "stage.round",
    "review.finding",
    "gate.allow",
    "gate.block",
    "gate.escalate",
    "owner.decision",
    "authz.denied",
    "authz.ask",
    "input.rejected",
    "verify.pass",
    "verify.fail",
    "pr.merged",
}
LEVELS = {"INFO", "WARN", "ERROR"}
OUTCOMES = {"success", "failure", "denied"}
REQUIRED = ("ts", "level", "service", "version", "event", "outcome", "actor", "change", "stage", "request_id")


def event(
    event: str,
    outcome: str,
    *,
    service: str,
    version: str,
    actor: str,
    request_id: str,
    change: str = "",
    stage: str = "",
    level: str = "INFO",
    reason: str = "",
    stream=None,
    **fields,
) -> dict:
    if event not in EVENTS or level not in LEVELS or outcome not in OUTCOMES:
        raise ValueError(f"bad log event {event}/{level}/{outcome}")
    rec = {
        "ts": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "level": level,
        "service": service,
        "version": version,
        "event": event,
        "outcome": outcome,
        "reason": reason,
        "actor": actor,
        "change": change,
        "stage": stage,
        "request_id": request_id,
    }
    for k, v in fields.items():
        rec[k] = v if isinstance(v, (int, float, bool)) else clean(v)
    for k in ("reason", "actor", "change", "stage", "request_id", "service", "version"):
        rec[k] = clean(rec[k], 120)
    line = json.dumps(rec, ensure_ascii=False)
    print(line, file=stream or sys.stdout, flush=True)
    return rec
