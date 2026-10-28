# appsec-baseline

AppSec-owned security baseline for the AI-native S-SDLC lab (`ai-sdlc-lab`). App repositories and their CI read this repository **at a pinned commit**; they never write to it, and their agents never load it from a PR branch.

| Path | What |
|---|---|
| `requirements/security-requirements.md` | SR-001…SR-031 (MUST/SHOULD): concrete parameters (limits, algorithms, headers, log format), triggers, OWASP ASVS 5.0 and Top 10:2025 references, required evidence, lab exceptions |
| `templates/` | `TRACE.md` (security traceability) and `THREAT.md` (threat model), written per change as `TRACE-<NNNN>.md` / `THREAT-<NNNN>.md`; `intent.md`, `spec.md`, `plan.md` are legacy (the stage templates live in the product repo) |
| `agents/` | Read-only agents, run as subagents of the product repo's local stage loop: `security-requirements-auditor` (intent, spec), `security-architect` (spec, plan), `security-code-reviewer` (code), `workflow-iac-reviewer` (code touching `.github/` or `infra/`); `security-tester` is dormant (CI comparison arm) |
| `skills/` | Checklists preloaded into `security-code-reviewer` and `security-tester`: `injection-input`, `authn-authz`, `secrets-pii-logging` |
| `schemas/` | `findings.schema.json` (reviewer output), `review-report.schema.json` (committed review reports), `sr-exceptions.schema.json` |
| *When they run* | Locally, per stage of a change (product repo `stages.yml`). CI runs no AI: `.github/workflows/verify.yml` checks the committed reports, scripts and scanners |
| `exceptions/` | `sr-exceptions.yml` (owner-accepted SR risks, max 180 days) and scanner exceptions, read at the pinned commit so a PR cannot add its own |
| `gate/security_gate.py` | Deterministic allow / block / questions / escalate over reviewer outputs and SARIF; sets each finding's status; any SR finding goes to the owner |
| `stage/` | Scripts of the stage loop and the CI verifier: validate, hash, write_artifact, structure, crosscheck, plan_drift, named_tests, classify, verify, log, render |
| `semgrep/` | Lab Semgrep rules (TLS: no `http://`, no disabled certificate checks) |

## Use locally

The repository is a Claude Code plugin marketplace whose root is the `appsec-review` plugin:

```
/plugin install appsec-review --marketplace ai-sdlc-lab/appsec-baseline
```

## Gate

```
pip install -r gate/requirements.txt
python gate/security_gate.py --reviewer security-architect=out/architect.json --sarif out/semgrep.sarif
```

Exit codes: `0` allow, `1` block, `2` escalate.
