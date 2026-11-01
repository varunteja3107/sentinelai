import json
import os
import getpass
import urllib.request
import urllib.error
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path.cwd() / ".env")

BASE_URL = "http://127.0.0.1:8000"

DEMO_RULES = [
    {
        "name": "DEMO_HTTPS_ALLOW",
        "source": "Any",
        "destination": "Any",
        "port": "443",
        "protocol": "TCP",
        "action": "ALLOW",
        "priority": 10,
        "description": "DEMO_ Allow secure HTTPS traffic."
    },
    {
        "name": "DEMO_HTTP_MONITOR",
        "source": "Any",
        "destination": "Any",
        "port": "80",
        "protocol": "TCP",
        "action": "MONITOR",
        "priority": 20,
        "description": "DEMO_ Monitor HTTP traffic without blocking."
    },
    {
        "name": "DEMO_TELNET_BLOCK",
        "source": "Any",
        "destination": "Any",
        "port": "23",
        "protocol": "TCP",
        "action": "BLOCK",
        "priority": 30,
        "description": "DEMO_ Block insecure Telnet traffic."
    },
    {
        "name": "DEMO_RDP_BLOCK",
        "source": "Any",
        "destination": "Any",
        "port": "3389",
        "protocol": "TCP",
        "action": "BLOCK",
        "priority": 40,
        "description": "DEMO_ Block unauthorized remote desktop traffic."
    },
    {
        "name": "DEMO_DNS_ALLOW",
        "source": "Any",
        "destination": "Any",
        "port": "53",
        "protocol": "UDP",
        "action": "ALLOW",
        "priority": 50,
        "description": "DEMO_ Allow DNS traffic."
    }
]


def api_request(path, method="GET", payload=None, token=None):
    data = None
    headers = {"Content-Type": "application/json"}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(
        BASE_URL + path,
        data=data,
        headers=headers,
        method=method
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        details = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"API error {error.code}: {details}"
        ) from error
    except urllib.error.URLError as error:
        raise RuntimeError(
            f"Cannot connect to SentinelAI backend: {error.reason}"
        ) from error


def main():
    print("\nSentinelAI Demo Firewall Seeder")
    print("--------------------------------")

    username = input("Admin username: ").strip()
    password = getpass.getpass("Admin password: ")

    login = api_request(
        "/api/auth/login",
        method="POST",
        payload={
            "username": username,
            "password": password
        }
    )

    token = login.get("access_token")

    if not token:
        raise RuntimeError("Login response did not contain an access token.")

    print("\nAdmin authentication successful.")

    existing_data = api_request(
        "/api/firewall/rules",
        token=token
    )

    if isinstance(existing_data, dict):
        existing_rules = existing_data.get(
            "rules",
            existing_data.get("items", [])
        )
    elif isinstance(existing_data, list):
        existing_rules = existing_data
    else:
        existing_rules = []

    existing_names = {
        rule.get("name")
        for rule in existing_rules
        if isinstance(rule, dict)
    }

    created = 0
    skipped = 0

    for rule in DEMO_RULES:
        if rule["name"] in existing_names:
            print(f"SKIPPED: {rule['name']} already exists")
            skipped += 1
            continue

        result = api_request(
            "/api/firewall/rules",
            method="POST",
            payload=rule,
            token=token
        )

        print(
            f"CREATED: {rule['name']} "
            f"| ID: {result.get('id', 'created')} "
            f"| Action: {rule['action']}"
        )
        created += 1

    print("\nVerification")
    print("-------------")

    verified_data = api_request(
        "/api/firewall/rules",
        token=token
    )

    if isinstance(verified_data, dict):
        verified_rules = verified_data.get(
            "rules",
            verified_data.get("items", [])
        )
    elif isinstance(verified_data, list):
        verified_rules = verified_data
    else:
        verified_rules = []

    verified_names = {
        rule.get("name")
        for rule in verified_rules
        if isinstance(rule, dict)
    }

    for rule in DEMO_RULES:
        status = "PASS" if rule["name"] in verified_names else "MISSING"
        print(f"{status}: {rule['name']}")

    print(f"\nCreated: {created}")
    print(f"Skipped: {skipped}")
    print(f"Total rules returned by API: {len(verified_rules)}")

    missing = [
        rule["name"]
        for rule in DEMO_RULES
        if rule["name"] not in verified_names
    ]

    if missing:
        print("\nSome rules could not be verified:", ", ".join(missing))
    else:
        print("\nAll five demo firewall policies are verified.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"\nFAILED: {error}")
        raise SystemExit(1)
