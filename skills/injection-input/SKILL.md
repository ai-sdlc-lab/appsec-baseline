---
name: injection-input
description: "Checklist for injection and input-handling flaws: server-side validation, query/command/path/key injection, DOM XSS, upload content handling, response headers, error leakage."
---

# injection-input checks

Used by the security-tester agent. Apply these checks to the code in scope and report only issues in this area, each with a quoted line of code and the attacker-controlled source.

- External input reaching a query, shell command, file path, object-storage key, template, `eval`/`exec`, deserialiser or regex without validation or a safe API (SR-001, SR-002).
- Validation done only in the browser, or validation that does not match the spec's *Inputs* table (SR-001).
- Untrusted data rendered with `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` or URL sinks (`href`, `src`) without scheme checks (SR-003).
- Uploads: size checked after reading the whole body, type trusted from the extension or `Content-Type` header, no magic-byte check, user filename used in a key or path, image decoded before a dimension check (SR-007 to SR-011).
- Missing or wrong response headers on new endpoints (SR-004); error responses that leak internals (SR-005).
