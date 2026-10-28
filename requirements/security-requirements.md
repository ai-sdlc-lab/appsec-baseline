# Security requirements

Owner: AppSec (this repository). App repositories and their agents read this file at a pinned commit; they never edit it.

## Conventions

- **MUST / MUST NOT / SHOULD / MAY** as in RFC 2119 and RFC 8174. A SHOULD may be deviated from only with a written justification in the spec (the auditor checks for it).
- **Applies when**: triggers from the table below; a requirement applies if any of its triggers is true for the change.
- **Refs**: OWASP ASVS 5.0 requirement or section IDs (checked against `OWASP/ASVS` `5.0/en`, 2026-10-22) and the OWASP Top 10:2025 category. `—` where there is no equivalent; the other source is named.
- **Evidence**: what must exist for the auditor to mark the requirement *covered*.
- **Lab exception**: where this lab deliberately deviates (cost or platform limits). Each exception is also listed in lab-admin `docs/BASELINE.md`.
- Numbers are lab values. They are deliberately strict and can be tuned later; changing one needs a PR here.

| Trigger | True when the change… |
|---|---|
| `INPUT` | accepts data from users or other external sources (body, query, path, headers, files, metadata) |
| `ENDPOINT` | adds or changes an HTTP endpoint or a served page |
| `WRITE` | lets a caller create, change or delete data |
| `FILE` | accepts, stores, transforms or serves files |
| `AUTHN` | adds or changes how callers or operators are identified |
| `AUTHZ` | exposes data or actions that differ by caller, owner or role |
| `CRYPTO` | encrypts, hashes, signs, generates tokens or random identifiers, or configures TLS |
| `DATA` | stores, transmits or processes personal or sensitive data |
| `LOG` | adds or changes logging |
| `SECRET` | uses credentials, keys or tokens |
| `DEP` | adds or updates a dependency, base image, tool or action |
| `IAC` | changes infrastructure or IAM |
| `CI` | changes CI/CD workflows or their permissions |
| `AI` | adds or changes LLM or agent behaviour, prompts or tools |

---

## A. Input and output

### SR-001 Input validation (MUST)
Every external input is validated on the server against an explicit schema before use:
- request models reject unknown fields (Pydantic `extra="forbid"` or equivalent);
- every string has a maximum length, an allowed character set or pattern, and is valid UTF-8; control characters are rejected unless the spec allows them;
- every number has a minimum and maximum; every enumerated value is checked against an allow list;
- JSON request bodies are limited to 64 KiB (uploads: SR-008);
- validation failure returns `422` with the SR-005 error body and is logged as `input.rejected` (SR-024).
Client-side validation is only for usability.
- Applies when: `INPUT`
- Refs: ASVS 2.2.1, 2.2.2 · A05:2025
- Evidence: spec *Inputs* table with a type and limit for every field; tests `test_*_rejects_*` per rejected class

### SR-002 Injection-safe interfaces (MUST)
Untrusted data never reaches an interpreter as code:
- queries use parameterised APIs; no string-built SQL/NoSQL/query expressions;
- no shell: `subprocess` with `shell=True`, `os.system` and equivalents are not used; commands, if any, take argument lists of fixed executables;
- object-storage keys and file paths are built only from server-generated values (SR-012);
- `eval`, `exec`, `pickle`, `yaml.load` (non-safe), `marshal` and similar are never applied to untrusted data.
- Applies when: `INPUT`
- Refs: ASVS 1.2.4, 1.2.5, V1.5 · A05:2025
- Evidence: Semgrep CE clean on injection and deserialisation rules; security-tester (injection-input checks) clean

### SR-003 Output encoding (MUST)
- API responses are produced by a JSON serialiser, never by string concatenation.
- The web frontend renders untrusted data only through text APIs (`textContent`, `setAttribute` for non-URL attributes); `innerHTML`, `outerHTML`, `insertAdjacentHTML` and `document.write` are not used with untrusted data.
- URLs from the API are accepted for `src`/`href` only if they parse as `https:` URLs on an expected host.
- Applies when: `INPUT`, `ENDPOINT`
- Refs: ASVS 1.2.1, 1.2.2, 1.2.3 · A05:2025
- Evidence: Semgrep CE clean on DOM-XSS rules; test that a breed or filename containing `<script>` renders as text

### SR-004 Response headers (MUST)
Every response carries:
- `Content-Type` matching the body, with `charset=utf-8` for text types;
- `X-Content-Type-Options: nosniff`;
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`;
- `Referrer-Policy: no-referrer`.

HTML responses additionally carry:
- `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' https://<image-host>; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'` (`<image-host>` is the regional S3 host; no `unsafe-inline`, no `unsafe-eval`);
- `Cross-Origin-Opener-Policy: same-origin`.

API responses with user-specific data carry `Cache-Control: no-store`. No CORS headers are sent unless the spec defines allowed origins; `Access-Control-Allow-Origin: *` is never combined with credentials.
- Applies when: `ENDPOINT`
- Refs: ASVS 3.4.1, 3.4.2, 3.4.3, 3.4.4, 3.4.5, 3.4.6, 3.4.8, 4.1.1 · A02:2025
- Evidence: test `test_security_headers` asserting exact values; ZAP baseline with no header alerts

## B. Exceptional conditions

### SR-005 Fail closed, generic errors (MUST)
- A last-resort exception handler catches every unhandled exception.
- Error responses use one fixed body: `{"error": "<code>", "request_id": "<id>"}`. They never contain stack traces, exception messages, file paths, SQL, library versions or internal hostnames.
- Status codes: `4xx` for caller errors with a stable `<code>`, `500` for unexpected errors, `503` for dependency failures.
- Any error during validation, authentication, authorisation, scanning or a write **denies** the operation (fail closed); a multi-step write leaves no partial state (clean up or roll back).
- Unhandled exceptions are logged once as `error.unhandled` with the request ID (SR-024).
- Applies when: `ENDPOINT`
- Refs: ASVS 16.5.1, 16.5.3, 16.5.4 · A10:2025
- Evidence: test that forces an internal error and asserts the exact generic body and a `503`/`500`; test that a failing check denies

### SR-006 Dependency failures and timeouts (MUST)
- Every outbound call (AWS SDK, HTTP) sets explicit timeouts: connect ≤ 3 s, read ≤ 5 s, and the total stays below the function timeout.
- Retries are bounded (at most 2, with backoff) and only for idempotent calls.
- A failed dependency produces `503` with the SR-005 body, never a fallback that skips a security check.
- Resources (files, streams, temporary objects) are released with context managers or `finally`.
- Applies when: `ENDPOINT`, `FILE`
- Refs: ASVS 16.5.2, 16.5.3 · A10:2025
- Evidence: botocore `Config` with timeouts and retries in code; test with a failing S3 stub asserting `503`

### SR-007 Resource and abuse limits (MUST)
- Function timeout ≤ 10 s; memory fixed in IaC.
- Endpoints that write or do heavy work SHOULD enforce a per-identity rate limit (lab value: 10 writes per user per minute) where the platform allows it.
- Concurrency MUST be capped per function once the account quota permits reserved concurrency.
- Applies when: `WRITE`, `FILE`, `ENDPOINT`
- Refs: ASVS 2.4.1, 15.2.2 · A06:2025
- Evidence: IaC values; spec *Limits* section; test for the rate limit if implemented
- Lab exception: the account Lambda concurrency limit is 10 (shared), so reserved concurrency is not possible; gap recorded in BASELINE

## C. File handling

### SR-008 Upload size (MUST)
At most 5 MiB per file. The limit is enforced from `Content-Length` before reading, and again while streaming, before any processing or storage. Larger requests get `413`.
- Applies when: `FILE`
- Refs: ASVS 5.2.1 · A06:2025
- Evidence: test `test_upload_rejects_oversize` (5 MiB + 1 byte)

### SR-009 Upload type allow list (MUST)
Only JPEG, PNG and WebP are accepted. A file is accepted only if the extension, the magic bytes **and** a successful decode by the image library all agree. Everything else gets `415`. The client's `Content-Type` header is not trusted.
- Applies when: `FILE`
- Refs: ASVS 5.2.2 · A05:2025
- Evidence: tests for a wrong extension, a renamed non-image (e.g. HTML or SVG as `.jpg`), and a truncated image

### SR-010 Image dimensions and decode safety (MUST)
Images are limited to 4096 × 4096 px and 16 megapixels, checked from the image header before full decoding. The decoder's decompression-bomb protection is enabled (Pillow `Image.MAX_IMAGE_PIXELS` set to the limit, warnings treated as errors).
- Applies when: `FILE`
- Refs: ASVS 5.2.6 · A06:2025
- Evidence: test `test_upload_rejects_pixel_flood`

### SR-011 Re-encode and strip metadata (MUST)
Every accepted image is re-encoded by the server (to JPEG or WebP) and only the re-encoded file is stored. This drops all metadata (EXIF, XMP, IPTC, GPS) and neutralises polyglot files.
- Applies when: `FILE`
- Refs: ASVS 5.2.2, 14.2.4 · A04:2025 (data exposure)
- Evidence: test that a stored image has no EXIF/GPS and differs byte-wise from the upload

### SR-012 Server-generated storage keys (MUST)
Storage keys are `<prefix>/<random-id>.<ext>`, where `<random-id>` has at least 128 bits from a CSPRNG (SR-021) and `<ext>` comes from the detected type. The client's filename is never used in a key or path. If the spec displays it, it is truncated to 100 characters and output-encoded.
- Applies when: `FILE`
- Refs: ASVS 5.3.2, 5.4.1, 5.4.2 · A01:2025
- Evidence: test that a filename such as `../../x.jpg` does not appear in the stored key

### SR-013 Inert serving (MUST)
Uploaded files are served only from object storage through presigned GET URLs valid for at most 15 minutes. The object's `Content-Type` is fixed at upload from the detected type, with `Content-Disposition: inline; filename="<random-id>.<ext>"`. Files are never executed and never served as HTML from the application origin.
- Applies when: `FILE`
- Refs: ASVS 5.3.1, 3.4.4 · A05:2025
- Evidence: test of stored object metadata; presigned URL expiry ≤ 900 s in code

### SR-014 Malware scanning and quarantine (MUST)
Uploads land in a quarantine prefix that is never listed or served. They are promoted to the public prefix only after a maintained signature-based scanner (for example ClamAV, signatures at most 24 h old) returns clean. A scan error, timeout or unknown result keeps the file quarantined (fail closed) and logs `upload.quarantined`. Infected files are deleted and logged as `upload.malware_detected`.
- Applies when: `FILE`
- Refs: ASVS 5.4.3 · A10:2025
- Evidence: spec *Quarantine* flow; tests that a quarantined file is not listed and that a scanner failure keeps it quarantined (EICAR test file for detection)

### SR-015 Per-user quota (MUST)
Per user: at most 20 uploads and 50 MiB per rolling 24 hours, and 200 MiB stored in total. Exceeding a limit gets `429` and is logged as `ratelimit.exceeded`.
- Applies when: `FILE`, `WRITE`
- Refs: ASVS 5.2.4 · A06:2025
- Evidence: test `test_upload_quota`

## D. Authentication and sessions

### SR-016 Managed identity provider, OIDC code flow (MUST)
Authentication is delegated to a managed OpenID Connect provider; the application stores no passwords and has no password endpoints.
- Browser sign-in uses the Authorization Code flow with PKCE (`S256`). The client validates `state` and `nonce`.
- The provider is configured to allow only the authorization-code grant for this client. Implicit (`token`) and password grants are disabled, and redirect URIs match exactly.
- Brute-force protection and account lockout are the provider's.
- Applies when: `AUTHN`
- Refs: ASVS V6.8, 10.2.1, V10.5, 10.4.1, 10.4.4, 10.4.6 · A07:2025
- Evidence: spec *Authentication* section naming the provider and flow; IaC for the provider client; test that unauthenticated writes return `401`

### SR-017 MFA on every account, phishing-resistant for privileged access (MUST)
Every account has MFA: application users, administrators, and the lab's operator accounts (AWS root and IAM users, GitHub, the Anthropic Console).
- **Allowed factors:** FIDO2/WebAuthn (passkeys, hardware security keys), and TOTP per RFC 6238.
- **Privileged and administrative accounts MUST use FIDO2/WebAuthn**; TOTP is allowed only for non-privileged users.
- **Not allowed:** SMS, voice calls, email codes, and push approvals without number matching.
- Biometrics only unlock a device-bound authenticator; they are never a factor on their own.
- There are no default, shared or generic accounts. Each factor can be revoked when lost.
- Applies when: `AUTHN`
- Refs: ASVS 6.3.2, 6.3.3, 6.5.1, 6.5.5, 6.5.6, 6.5.7, 6.6.1, 6.6.4 · A07:2025
- Evidence: provider MFA configuration in IaC (SMS/email factors disabled); BASELINE entries for operator accounts
- Note: TOTP's HMAC-SHA-1 is mandated by RFC 6238 and is the only allowed SHA-1 use (see SR-021)

### SR-018 Token validation (MUST)
Every bearer token is validated before use:
- the signature is checked against keys fetched only from the provider's pre-configured JWKS URL;
- the algorithm is on an allow list: `ES256`, `EdDSA` or `PS256`. `none`, the HMAC algorithms and `RS256` are rejected;
- `iss` matches exactly; `aud` matches this API; `exp` and `nbf` are checked with at most 60 s clock skew; the token type is an access token.
Access tokens live at most 60 minutes; refresh tokens have an absolute expiry of at most 24 hours.
- Applies when: `AUTHN`, `AUTHZ`
- Refs: ASVS 9.1.1, 9.1.2, 9.1.3, 9.2.1, 9.2.2, 9.2.3, 10.4.8 · A07:2025
- Evidence: tests for a wrong `aud`, an expired token, `alg: none`, and a token signed by another key
- Lab exception rule: ASVS 5.0 Appendix C marks RSA PKCS#1 v1.5 signatures (`RS256`) as disallowed. If the chosen provider can only sign with `RS256`, record a lab exception in BASELINE before using it.

### SR-019 Browser token and cookie handling (MUST)
- Tokens are never stored in `localStorage` or `sessionStorage`. They are kept in memory, or in a cookie that is `HttpOnly`, `Secure`, `SameSite=Lax` (`Strict` for administrative functions) and named with the `__Host-` prefix.
- Tokens never appear in URLs, logs or analytics (SR-024, SR-026).
- Applies when: `AUTHN`
- Refs: ASVS 3.3.1, 3.3.2, 3.3.3, 3.3.4, 14.2.1 · A07:2025
- Evidence: test asserting cookie attributes; review of the frontend storage code

## E. Authorisation

### SR-020 Server-side, deny-by-default authorisation (MUST)
- Every endpoint declares its required permission in code, and the default is deny.
- Object-level ownership is checked on every read, change and delete; unguessable IDs are not an access control.
- Authorisation decisions use only server-side identity from the validated token, never client-supplied `user_id` or role values.
- The spec's *Authorisation matrix* covers every action × role, and each cell has a test, including cross-user access.
- Applies when: `AUTHZ`, `WRITE`
- Refs: ASVS 8.2.1, 8.2.2, 8.3.1, 8.3.3 · A01:2025
- Evidence: authorisation matrix in the spec; tests `test_*_other_user_forbidden`; security-tester (authn-authz checks) clean

## F. Cryptography

### SR-021 Approved cryptography only (MUST)
Only vetted libraries are used: Python `cryptography`, `hashlib`, `hmac`, `secrets`; the Web Crypto API; AWS-managed services. No custom cryptography. Every primitive gives at least 128 bits of security. Approved algorithms follow ASVS 5.0 Appendix C:

| Purpose | Allowed | Forbidden |
|---|---|---|
| Authenticated encryption | AES-256-GCM (preferred), ChaCha20-Poly1305 | ECB, unauthenticated CBC/CTR/CFB/OFB, DES, 3DES, RC4 |
| Hashing | SHA-256, SHA-384, SHA-512, SHA3-256/384/512, BLAKE2b/2s, BLAKE3 | MD4, MD5, CRC for integrity; SHA-1 (except the TOTP note in SR-017) |
| MAC | HMAC-SHA-256/384/512 | HMAC-MD5, HMAC-SHA-1 |
| Signatures | Ed25519, ECDSA P-256/P-384, RSA-PSS with ≥ 3072-bit keys | RSA PKCS#1 v1.5 signatures, DSA |
| Key exchange | ECDH (X25519, P-256, P-384), as negotiated by TLS (SR-022) | RSA key transport (PKCS#1 v1.5) |
| Key derivation | HKDF | MD5- or SHA-1-based KDFs |
| Password hashing (only if a standard ever requires it; SR-016 forbids app passwords) | argon2id with t = 2, m ≥ 19 MiB, p = 1 | anything else |
| Random values | CSPRNG only: `secrets`, `os.urandom`, `crypto.getRandomValues`; ≥ 128 bits for tokens and IDs | `random`, `Math.random` for anything security-relevant |

Nonces and IVs are never reused with the same key. Every use of cryptography and every key is listed in the crypto inventory (lab-admin BASELINE).
- Applies when: `CRYPTO`, `SECRET`
- Refs: ASVS 11.2.1, 11.2.3, 11.3.1, 11.3.2, 11.3.3, 11.3.4, 11.4.1, 11.4.2, 11.5.1, 11.6.1, 11.6.2, Appendix C · A04:2025
- Evidence: Semgrep CE clean on crypto rules; crypto inventory updated

### SR-022 Encrypted transport only (MUST)
- Every connection, external and internal, uses TLS 1.2 or TLS 1.3 (1.3 preferred). Nothing listens on or connects over plaintext HTTP; `http://` URLs appear only for `localhost` in tests.
- Where we configure TLS, TLS 1.2 is limited to forward-secret AEAD suites (ECDHE with AES-GCM or ChaCha20-Poly1305).
- Certificates are publicly trusted, and certificate validation is never disabled (no `verify=False`, `--insecure`, `NODE_TLS_REJECT_UNAUTHORIZED=0`).
- S3 bucket policies deny requests where `aws:SecureTransport` is `false` and where `s3:TlsVersion` is below 1.2.
- Applies when: `ENDPOINT`, `IAC`, `CRYPTO`
- Refs: ASVS 12.1.1, 12.1.2, 12.2.1, 12.2.2, V12.3 · A04:2025
- Evidence: bucket policy in IaC; test that a TLS 1.1 handshake to the public endpoint fails; Semgrep CE clean on TLS-verification rules
- Lab exception: the Lambda function URL and S3 endpoints are AWS-managed, so their cipher suites are AWS's choice; covered by the TLS-version test

### SR-023 Encrypted storage only (MUST)
Every data store is encrypted at rest with AES-256. This covers S3 objects (default bucket encryption SSE-S3, uploads that request no or other encryption denied by policy), CloudWatch Logs, Lambda environment variables, and Terraform state. There are no unencrypted volumes, snapshots or exports. CI artifacts contain no personal or sensitive data.
- Applies when: `IAC`, `FILE`, `DATA`
- Refs: ASVS 14.2.4 · A04:2025 · lab BASELINE BL-13, BL-19
- Evidence: Checkov or Trivy clean on encryption checks; IaC encryption settings
- Lab exception: AWS-managed keys (SSE-S3 / service-default) instead of customer-managed KMS keys (cost constraint), so there is no customer-controlled key revocation

## G. Logging

### SR-024 Security logging format and events (MUST)
Security events are written as **JSON Lines** to stdout (collected by CloudWatch), one event per line, with values JSON-encoded so newlines and control characters cannot forge entries.

Mandatory fields:

| Field | Format |
|---|---|
| `ts` | RFC 3339 UTC with milliseconds, e.g. `2026-10-22T14:03:07.123Z` |
| `level` | `INFO`, `WARN` or `ERROR` |
| `event` | from the vocabulary below, `<area>.<action>`, in the style of the OWASP Logging Vocabulary |
| `outcome` | `success`, `failure` or `denied` |
| `request_id` | platform request ID, or a generated UUID |
| `actor` | pseudonymous subject ID (the provider's `sub`) or `anonymous`; never an email or name |
| `source_ip` | from the platform request context, never from `X-Forwarded-For` |
| `http` | `{method, path, status}`; the path has no query string |
| `resource` | `{type, id}` where applicable |
| `reason` | short machine code, e.g. `size_exceeded`, `type_not_allowed` |
| `service`, `version` | service name and git commit SHA |

Mandatory events: `authn.login`, `authn.logout`, `authz.denied`, `input.rejected`, `upload.accepted`, `upload.rejected`, `upload.quarantined`, `upload.malware_detected`, `upload.published`, `ratelimit.exceeded`, `error.unhandled`, `admin.change`.

**Never logged:** passwords, tokens, `Authorization` or `Cookie` headers, presigned URLs (they contain credentials), request or response bodies, file contents, email addresses, names.

The application role can write logs but not read or delete them.
- Applies when: `LOG`, `AUTHN`, `AUTHZ`, `INPUT`, `FILE`
- Refs: ASVS 16.2.1, 16.2.2, 16.2.4, 16.2.5, 16.3.1, 16.3.2, 16.3.3, V16.4 · A09:2025
- Evidence: shared logging helper with a schema test; tests asserting the event for a rejected upload and a denied access; security-tester (secrets-pii-logging checks) clean
- Lab exception: logs are retained 7 days (cost); production SHOULD keep at least 90 days

## H. Data protection

### SR-025 Data minimisation and inventory (MUST)
- Personal data is collected only as listed in the spec's *Data inventory*, with purpose, storage location and retention. Uploads are deleted when their owner deletes them or the account.
- Sensitive data never appears in URLs or query strings and is never sent to third parties. No trackers or analytics; fonts, scripts and styles come from the application origin.
- Applies when: `DATA`
- Refs: ASVS 14.2.1, 14.2.3, 14.2.4 · A01:2025
- Evidence: spec *Data inventory*; CSP (SR-004) blocks third-party origins; review

### SR-026 Secrets handling (MUST, with SHOULD for federation)
- **MUST:** no secret in code, repository history, container images, IaC, logs, issues or CI output. Push protection and gitleaks block commits containing secrets.
- **MUST:** an unavoidable static secret is stored only in a managed store: GitHub Actions secrets scoped to an environment, or AWS SSM Parameter Store `SecureString` with the AWS-managed key. Read access is least privilege, there is a named owner, and it is rotated at least every 90 days.
- **SHOULD:** use short-lived federated credentials (OIDC) instead of any static secret wherever the platform supports it. The lab does this for AWS and the Claude API.
- Applies when: `SECRET`, `CI`, `IAC`
- Refs: ASVS 13.3.1, 13.3.2 · A07:2025
- Evidence: gitleaks clean; workflows use OIDC; a secrets register in BASELINE for any static secret

## I. Supply chain

### SR-027 Pinned, vetted dependencies and build inputs (MUST)
- Application dependencies are pinned to exact versions in lockfiles with hashes: `pip install --require-hashes` (or an equivalent hashed lock), and `package-lock.json` with `npm ci`.
- Container base images are pinned by digest. CI tools are pinned by version and SHA-256. Third-party actions are pinned by commit SHA and come from the BL-01 allowlist.
- At merge there is no known vulnerability with CVSS ≥ 7.0 in any dependency (OSV-Scanner). Lower findings are fixed within 30 days or documented as exceptions.
- Releases SHOULD include a CycloneDX SBOM.
- Applies when: `DEP`, `CI`
- Refs: ASVS 15.2.1 · A03:2025
- Evidence: OSV-Scanner clean; lockfiles with hashes; pins visible in workflows and Dockerfiles

## J. Infrastructure

### SR-028 IAM least privilege (MUST)
- Policies name exact actions and resources. `"Action": "*"` is never used. `"Resource": "*"` only appears for actions that have no resource type, and each one is documented.
- Every role carries the `sdlc-lab-boundary` permissions boundary. `iam:PassRole` is conditioned on `iam:PassedToService`.
- Trust policies pin the repository ID plus an environment or a reusable-workflow SHA.
- There are no IAM user access keys. Human access uses `aws login` with MFA (SR-017).
- Applies when: `IAC`
- Refs: — (cloud IAM is out of ASVS scope; lab-admin BASELINE BL-10, BL-11, BL-12, BL-17) · A01:2025
- Evidence: Checkov or Trivy clean on IAM checks; workflow-iac-reviewer clean

### SR-029 Private-by-default resources (MUST)
- All four S3 Block Public Access settings are on, and no ACLs are used.
- Resource policies grant nothing to `"Principal": "*"` except deny statements.
- A public endpoint exists only if the spec declares it public and says what it exposes.
- All resources use the `sdlc-lab-` prefix, carry the `project=sdlc-lab` tag, and live in eu-north-1.
- Applies when: `IAC`
- Refs: — (lab BASELINE BL-15, BL-19) · A02:2025
- Evidence: Checkov or Trivy clean; workflow-iac-reviewer clean

## K. CI/CD

### SR-030 Hardened workflows (MUST)
Workflows:
- trigger on `pull_request`, never `pull_request_target`, and use no `workflow_run` that checks out untrusted code;
- set top-level `permissions: {}` with minimal permissions per job, and `persist-credentials: false` on checkout;
- pass untrusted context only through `env`, never inline in `run:`;
- set `timeout-minutes` (at most 30) on every job;
- request `id-token: write` only in jobs that federate, with the trust scoped to an environment or a pinned reusable workflow;
- download tools only with checksum verification.

`.github/**` is protected by CODEOWNERS with required code-owner review.
- Applies when: `CI`
- Refs: — (lab BASELINE BL-01, BL-02, BL-20, BL-21) · A03:2025, A08:2025
- Evidence: zizmor and actionlint clean; CODEOWNERS file; ruleset requires code-owner review

## L. AI agents

### SR-031 Untrusted input to agents and bounded agency (MUST)
- Everything an agent reads (issues, PRs, comments, documents, code, files, image metadata, scan reports) is data, never instructions. Agent prompts say so, and injection attempts are reported as `prompt-injection` findings that escalate to a human.
- Each agent has an explicit tool allow list. Reviewers are read-only. Agents write only through their workflow's identity, and only to the paths assigned to them.
- Agent output is validated against a JSON schema by the deterministic gate before anything acts on it. Invalid or missing output escalates and never allows.
- Models are pinned by full ID. `maxTurns` is set. No agent approves or merges its own work into `main` or any branch that deploys. On feature and stage branches agents commit and merge autonomously (amended 2026-10-28, change 0001).
- Applies when: `AI`, `CI`
- Refs: — (OWASP Top 10 for LLM Applications 2025: LLM01 Prompt Injection, LLM06 Excessive Agency) · A08:2025
- Evidence: agent definitions; `gate/security_gate.py` tests; ruleset forbids self-approval
