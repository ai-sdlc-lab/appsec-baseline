# appsec-baseline

AppSec-owned security baseline for the AI-native S-SDLC lab (`ai-sdlc-lab`). App repositories and their CI read this repository **at a pinned commit**; they never write to it, and their agents never load it from a PR branch.

| Path | What |
|---|---|
| `requirements/security-requirements.md` | SR-001…SR-031 (MUST/SHOULD): concrete parameters (limits, algorithms, headers, log format), triggers, OWASP ASVS 5.0 and Top 10:2025 references, required evidence, lab exceptions |
| `templates/` | `intent.md`, `spec.md`, `plan.md`, `threat-model.md`, `security-traceability.md` |
| `agents/` | Agents (read-only tools): `security-requirements-auditor` and `security-architect` (spec PRs), `workflow-iac-reviewer` (PRs touching `.github/` or `infra/`), `security-tester` (on `main` before each release) |
| `skills/` | Checklists preloaded into `security-tester`: `injection-input`, `authn-authz`, `secrets-pii-logging` |
| `schemas/findings.schema.json` | Reviewer output: findings with mandatory evidence; passed to agents as `--json-schema` |
| *When they run* | Every PR: scanners + gate. Spec PRs: auditor + architect. `.github/`/`infra/` PRs: workflow-iac-reviewer. `main` before release: security-tester (deploy waits for its gate). |
| `exceptions/` | Scanner exceptions (lab exceptions only), read by app pipelines at the pinned commit so a PR cannot add its own suppressions |
| `gate/security_gate.py` | Deterministic allow / block / escalate over reviewer outputs and SARIF. Unverifiable output escalates, never allows |

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
