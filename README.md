# appsec-baseline

AppSec-owned security baseline for the AI-native S-SDLC lab (`ai-sdlc-lab`). App repositories and their CI read this repository **at a pinned commit**; they never write to it, and their agents never load it from a PR branch.

| Path | What |
|---|---|
| `requirements/security-requirements.md` | SR-001…SR-025: statement, applicability triggers, OWASP ASVS 5.0 reference, required evidence |
| `templates/` | `intent.md`, `spec.md`, `plan.md`, `threat-model.md`, `security-traceability.md` |
| `agents/` | Reviewer agents (read-only tools): `security-requirements-auditor`, `security-architect`, `injection-input-reviewer`, `authn-authz-reviewer`, `secrets-pii-logging-reviewer`, `iac-reviewer` |
| `schemas/findings.schema.json` | Reviewer output: findings with mandatory evidence; passed to agents as `--json-schema` |
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
