import ssl

import httpx
import requests

session = requests.Session()

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
# ruleid: sr022-requests-verify-false
session.verify = False
# ruleid: sr022-unverified-ssl-context
ctx.check_hostname = False
# ruleid: sr022-unverified-ssl-context
ctx.verify_mode = ssl.CERT_NONE
# ruleid: sr022-plain-http-url
EVIL = "http://localhost.evil.example/x"
# ruleid: sr022-plain-http-url
EVIL2 = "http://127.0.0.10/x"
