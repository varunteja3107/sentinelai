import json
import getpass
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"

DEMO_IPS = {
    "192.0.2.101",
    "198.51.100.101",
    "198.51.100.102",
    "198.51.100.103",
    "198.51.100.104",
}

def api(path, token=None, payload=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    data = json.dumps(payload).encode() if payload is not None else None

    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        headers=headers,
        method="POST" if data else "GET"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            f"{path}: HTTP {error.code}: "
            f"{error.read().decode(errors='replace')}"
        )

def records(data, key):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get(key, data.get("items", []))
    return []

def main():
    print("\nSentinelAI Demo Environment Verification")
    print("========================================")

    username = input("Admin username: ").strip()
    password = getpass.getpass("Admin password: ")

    login = api(
        "/api/auth/login",
        payload={"username": username, "password": password}
    )
    token = login["access_token"]
    print("\nAuthentication: PASS")

    threats = records(api("/api/threats"), "threats")
    incidents = records(api("/api/incidents"), "incidents")
    rules = records(api("/api/firewall/rules", token), "rules")
    sessions = records(api("/api/sessions", token), "sessions")
    logs = records(api("/api/logs", token), "logs")

    demo_threats = [
        t for t in threats
        if t.get("source_ip") in DEMO_IPS
    ]

    demo_incidents = [
        i for i in incidents
        if i.get("threat_id") in {78, 79, 81}
    ]

    demo_rules = [
        r for r in rules
        if str(r.get("name", "")).startswith("DEMO_")
    ]

    demo_sessions = [
        s for s in sessions
        if str(s.get("user", "")).startswith("DEMO_")
    ]

    demo_logs = [
        log for log in logs
        if (
            log.get("source_ip") in DEMO_IPS
            or "DEMO_" in str(log.get("message", ""))
        )
    ]

    print("\nModule verification")
    print("-------------------")
    print(f"Threat records: {len(demo_threats)} / 5 expected")
    print(f"Incidents from demo BLOCK threats: {len(demo_incidents)} / 3 expected")
    print(f"Firewall demo rules: {len(demo_rules)} / 5 expected")
    print(f"Persistent demo sessions: {len(demo_sessions)} / 3 expected")
    print(f"Related audit events: {len(demo_logs)}")

    print("\nDemo threat results:")
    for t in demo_threats:
        print(
            f"ID {t.get('id')} | {t.get('threat_type')} | "
            f"Risk {t.get('risk_score')} | "
            f"{t.get('severity')} | {t.get('action')}"
        )

    print("\nDemo incidents:")
    for i in demo_incidents:
        print(
            f"ID {i.get('id')} | {i.get('title')} | "
            f"{i.get('severity')} | {i.get('status')}"
        )

    print("\nDemo sessions:")
    for s in demo_sessions:
        print(
            f"{s.get('user')} | Risk {s.get('risk')} | "
            f"{s.get('decision')} | {s.get('status')}"
        )

    print("\nVerification finished. Existing records were not modified.")

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"\nVERIFICATION ERROR: {error}")
        raise SystemExit(1)
