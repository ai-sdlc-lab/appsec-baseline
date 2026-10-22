---
name: authn-authz
description: "Checklist for authentication and authorisation flaws: unauthenticated writes, missing ownership checks (IDOR), client-side-only checks, token handling, default accounts."
---

# authn-authz checks

Used by the security-tester agent. Apply these checks to the code in scope and report only issues in this area, each with a quoted line of code and the attacker-controlled source.

- **Authentication (SR-016):** a write or user-specific endpoint reachable without a validated token; any password handling in the app; OIDC flow other than Authorization Code + PKCE `S256`; missing `state`/`nonce` checks; implicit or password grants enabled; non-exact redirect URIs.
- **MFA (SR-017):** identity-provider configuration allowing SMS, voice or email factors; privileged roles without WebAuthn; default or shared accounts.
- **Tokens (SR-018):** signature not verified; keys taken from the token (`jku`, `x5u`, embedded `jwk`) instead of the pinned JWKS URL; algorithm not restricted to `ES256`/`EdDSA`/`PS256` (accepting `none`, HMAC or `RS256`); `iss`/`aud`/`exp`/`nbf` not checked or skew > 60 s; access tokens > 60 min; refresh tokens without an absolute expiry ≤ 24 h.
- **Browser storage (SR-019):** tokens in `localStorage`/`sessionStorage` or URLs; cookies missing `HttpOnly`, `Secure`, `SameSite`, `__Host-` prefix.
- **Authorisation (SR-020):** endpoints without a declared permission (allow by default); object access by ID without an ownership check; list endpoints returning other users' objects; decisions based on client-supplied `user_id`/role; cells of the spec's *Authorisation matrix* not enforced or not tested.
