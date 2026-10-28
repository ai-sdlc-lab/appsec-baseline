import pytest
from redact import redact

SECRETS = [
    "sk-ant-oat01-AbCdEfGh123456_-xyz",
    ".".join(["eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJyZXBvOngifQ", "c2lnbmF0dXJlLXZhbHVl"]),  # noqa: FLY002 (no literal token)
    "ghs_" + "a" * 36,
    "github_pat_" + "B" * 40,
    "ASIA" + "ABCDEFGHIJKLMNOP",
    "aws_secret_access_key = " + "x" * 40,
    "https://b.s3.eu-north-1.amazonaws.com/k?X-Amz-Credential=AKIAX%2F2026&X-Amz-Signature=abc123",
]


@pytest.mark.parametrize("secret", SECRETS)
def test_redacts(secret):
    out, n = redact(f"evidence: {secret} end")
    assert n >= 1 and "[REDACTED]" in out
    for fragment in ("sk-ant-oat01-AbCd", "eyJzdWIi", "a" * 36, "B" * 40, "ABCDEFGHIJKLMNOP", "x" * 40, "abc123"):
        assert fragment not in out


def test_leaves_normal_evidence_alone():
    text = 'api/app/main.py:42 `if not BREED.match(breed):` returns 404 for "eyJ" prefixes'
    assert redact(text) == (text, 0)
