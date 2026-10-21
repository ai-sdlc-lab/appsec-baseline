---
name: authn-authz
description: "Checklist for authentication and authorisation flaws: unauthenticated writes, missing ownership checks (IDOR), client-side-only checks, token handling, default accounts."
---

# authn-authz checks

Used by the security-tester agent. Apply these checks to the code in scope and report only issues in this area, each with a quoted line of code and the attacker-controlled source.

- New or changed endpoints that write data, or return user-specific data, without authentication (SR-014).
- Object access by ID without an ownership or role check on the server; list endpoints leaking other users' objects (SR-015).
- Authorisation decided from client-supplied values (a `user_id` or `role` in the body or query, hidden form fields, JWT claims not verified) (SR-015).
- Token or session handling: unverified signatures, missing audience/issuer/expiry checks, tokens in URLs or logs (SR-014, SR-018).
- Default credentials, shared accounts, or admin paths without extra protection (SR-016).
- Compare the code with the spec's *Authorisation matrix*; every cell must be enforced.
