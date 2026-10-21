---
name: secrets-pii-logging
description: "Checklist for secrets, personal data and logging flaws: hard-coded or stored credentials, secrets or PII in logs/URLs/errors, missing security event logs, image metadata retention."
---

# secrets-pii-logging checks

Used by the security-tester agent. Apply these checks to the code in scope and report only issues in this area, each with a quoted line of code and the attacker-controlled source.

- Hard-coded secrets, keys, tokens or passwords, including in tests, fixtures, examples and workflow files; long-lived credentials where federation is expected (SR-020).
- Secrets, tokens, personal data or full request bodies written to logs, URLs, query strings or error messages (SR-018).
- Security events the spec requires but the code does not log: authentication results, authorisation failures, rejected input (SR-017).
- Personal data stored beyond the spec's *Data inventory*, or image metadata (EXIF GPS) kept (SR-019).
- Workflows exposing secrets to untrusted code or printing credentials (SR-020, SR-024).
