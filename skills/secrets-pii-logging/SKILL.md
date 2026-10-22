---
name: secrets-pii-logging
description: "Checklist for secrets, personal data and logging flaws: hard-coded or stored credentials, secrets or PII in logs/URLs/errors, missing security event logs, image metadata retention."
---

# secrets-pii-logging checks

Used by the security-tester agent. Apply these checks to the code in scope and report only issues in this area, each with a quoted line of code and the attacker-controlled source.

- **Secrets (SR-026):** keys, tokens, passwords or connection strings in code, tests, fixtures, examples, Dockerfiles, IaC or workflow files; static secrets where OIDC federation is available; secrets printed in CI output.
- **Crypto (SR-021):** MD5, SHA-1 (outside TOTP), DES/3DES/RC4, ECB or unauthenticated modes, RSA PKCS#1 v1.5, `random`/`Math.random` for tokens or IDs, IDs with < 128 bits of randomness, custom crypto.
- **Transport (SR-022):** `http://` URLs outside localhost tests; TLS verification disabled (`verify=False`, `--insecure`, `NODE_TLS_REJECT_UNAUTHORIZED=0`).
- **Logging format (SR-024):** security events not using the shared JSON Lines helper; mandatory fields (`ts` RFC 3339 UTC ms, `level`, `event`, `outcome`, `request_id`, `actor`, `source_ip`, `http`, `resource`, `reason`, `service`, `version`) missing; `source_ip` taken from `X-Forwarded-For`; mandatory events (`authn.*`, `authz.denied`, `input.rejected`, `upload.*`, `ratelimit.exceeded`, `error.unhandled`, `admin.change`) not emitted; values not JSON-encoded (log injection).
- **Never logged (SR-024):** passwords, tokens, `Authorization`/`Cookie` headers, **presigned URLs**, request/response bodies, file contents, emails, names.
- **Data (SR-025, SR-011):** personal data beyond the spec's *Data inventory*; sensitive data in URLs/query strings; third-party scripts, fonts or analytics; image metadata kept.
