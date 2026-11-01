import getpass
import json
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8001"

def request(method, path, data=None, token=None):
    body = None if data is None else json.dumps(data).encode("utf-8")
    headers = {"Content-Type": "application/json"}

    if token:
        headers["Authorization"] = "Bearer " + token

    req = urllib.request.Request(
        BASE + path,
        data=body,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        return exc.code, {}

username = input("Admin username: ").strip()
password = getpass.getpass("Admin password (hidden): ")

status, result = request(
    "POST",
    "/api/auth/login",
    {"username": username, "password": password},
)
password = None

if status != 200 or not result.get("access_token"):
    print(f"FAIL: Login returned HTTP {status}.")
    raise SystemExit(1)

token = result["access_token"]
print("PASS: Admin login succeeded.")

status, _ = request("POST", "/api/auth/logout", token=token)

if status != 200:
    print(f"FAIL: Logout returned HTTP {status}.")
    raise SystemExit(1)

print("PASS: Server-side logout succeeded.")

status, _ = request(
    "GET", "/api/response-actions", token=token
)

if status != 401:
    print(f"FAIL: Old token returned HTTP {status}; expected 401.")
    raise SystemExit(1)

print("PASS: Revoked token returns HTTP 401.")
print("All three security checks passed.")
