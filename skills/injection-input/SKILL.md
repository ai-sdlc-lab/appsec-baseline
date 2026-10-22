---
name: injection-input
description: "Checklist for injection and input-handling flaws: server-side validation, query/command/path/key injection, DOM XSS, upload content handling, response headers, error leakage."
---

# injection-input checks

Used by the security-tester agent. Apply these checks to the code in scope and report only issues in this area, each with a quoted line of code and the attacker-controlled source.

- **Validation (SR-001):** request models without `extra="forbid"`; strings without a max length or pattern; numbers without bounds; JSON bodies over 64 KiB accepted; validation only in the browser; rejections not returning `422` or not logged as `input.rejected`.
- **Injection (SR-002):** untrusted data reaching a query, `subprocess(..., shell=True)`, `os.system`, a file path, an S3 key, `eval`/`exec`, `pickle`, non-safe `yaml.load`, or a regex built from input.
- **Output encoding (SR-003):** untrusted data in `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`; API URLs assigned to `src`/`href` without an `https:` + expected-host check; JSON built by string concatenation.
- **Headers (SR-004):** missing or different values for `X-Content-Type-Options`, `Strict-Transport-Security` (max-age 31536000), `Referrer-Policy: no-referrer`, the exact CSP (no `unsafe-inline`/`unsafe-eval`, `frame-ancestors 'none'`), `Cross-Origin-Opener-Policy`; CORS headers not defined in the spec.
- **Errors (SR-005, SR-006):** stack traces, exception text, paths or versions in responses; missing last-resort handler; fail-open paths (an exception in a check that lets the request continue); outbound calls without connect/read timeouts or with unbounded retries; dependency failure not mapped to `503`; partial writes left behind.
- **Uploads (SR-008 to SR-015):** size checked after reading the body (limit 5 MiB, `413`); type trusted from extension or `Content-Type` instead of extension + magic bytes + decode (JPEG/PNG/WebP only, `415`); dimensions not checked before decode (4096 × 4096, 16 MP) or Pillow bomb protection off; image stored without server-side re-encoding (metadata kept); client filename in a key or path; served from the app origin or without fixed `Content-Type`/`Content-Disposition`; published before a clean malware scan, or a scan error that publishes (fail open); quotas (20/day, 50 MiB/day, 200 MiB total) missing.
