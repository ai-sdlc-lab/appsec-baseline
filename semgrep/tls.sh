# ruleid: sr022-curl-insecure
curl --insecure https://example.org
# ruleid: sr022-curl-insecure
curl -k https://example.org
# ok: sr022-curl-insecure
curl -fsSL https://example.org
