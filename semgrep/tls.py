import ssl

import httpx
import requests

# ruleid: sr022-requests-verify-false
requests.get("https://example.org", verify=False)
# ok: sr022-requests-verify-false
requests.get("https://example.org")
# ruleid: sr022-requests-verify-false
httpx.get("https://example.org", verify=False)
# ruleid: sr022-unverified-ssl-context
ctx = ssl._create_unverified_context()
# ruleid: sr022-plain-http-url
URL = "http://example.org/api"
# ok: sr022-plain-http-url
LOCAL = "http://127.0.0.1:8080/api/health"
