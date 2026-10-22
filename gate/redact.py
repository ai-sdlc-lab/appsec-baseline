"""Redact credentials from reviewer output before it is posted or uploaded.

Reviewer output becomes a public PR comment and artifact (public repo), and an
agent can be steered into quoting secrets as "evidence". Patterns are deliberately
broad; a false positive only hides text.

Usage: redact.py FILE... (rewrites in place, prints the number of redactions)
"""

import re
import sys

PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}"),  # Anthropic keys and federated tokens
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),  # JWTs (OIDC tokens)
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),  # GitHub tokens
    re.compile(r"github_pat_[A-Za-z0-9_]{30,}"),
    re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),  # AWS access key IDs
    re.compile(r"(?i)(aws_secret_access_key|aws_session_token)[\"'\s:=]+[A-Za-z0-9/+=]{16,}"),
    re.compile(r"X-Amz-(?:Signature|Credential|Security-Token)=[^&\s\"']+"),  # presigned URL credentials
]


def redact(text: str) -> tuple[str, int]:
    total = 0
    for p in PATTERNS:
        text, n = p.subn("[REDACTED]", text)
        total += n
    return text, total


if __name__ == "__main__":
    count = 0
    for path in sys.argv[1:]:
        with open(path) as fh:
            new, n = redact(fh.read())
        if n:
            with open(path, "w") as fh:
                fh.write(new)
        count += n
    print(count)
