import json
import getpass
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"

SCENARIOS = [
    {
        "user": "DEMO_TRUSTED_ADMIN",
        "device": "DEMO_Trusted_MacBook",
        "resource": "Security Dashboard",
        "location": "Bangalore",
        "risk_score": 10,
        "identity_verified": True,
        "device_trusted": True,
        "network_trusted": True,
        "device_compliant": True,
        "device_posture_score": 100,
        "failed_login_attempts": 0,
        "unusual_activity": False,
        "session_age_minutes": 30,
        "resource_sensitivity": "NORMAL",
        "expected": "ALLOW"
    },
    {
        "user": "DEMO_UNTRUSTED_DEVICE",
        "device": "DEMO_Unknown_Device",
        "resource": "Student Records",
        "location": "Bangalore",
        "risk_score": 10,
        "identity_verified": True,
        "device_trusted": False,
        "network_trusted": True,
        "device_compliant": True,
        "device_posture_score": 100,
        "failed_login_attempts": 0,
        "unusual_activity": False,
        "session_age_minutes": 20,
        "resource_sensitivity": "NORMAL",
        "expected": "MFA"
    },
    {
        "user": "DEMO_FLAGGED_LOCATION",
        "device": "DEMO_Remote_Device",
        "resource": "Placement Administration",
        "location": "Foreign",
        "risk_score": 10,
        "identity_verified": True,
        "device_trusted": True,
        "network_trusted": True,
        "device_compliant": True,
        "device_posture_score": 100,
        "failed_login_attempts": 0,
        "unusual_activity": False,
        "session_age_minutes": 10,
        "resource_sensitivity": "NORMAL",
        "expected": "MFA"
    },
    {
        "user": "DEMO_HIGH_RISK_ACCESS",
        "device": "DEMO_Suspicious_Device",
        "resource": "Critical Security Configuration",
        "location": "Unknown",
        "risk_score": 20,
        "identity_verified": True,
        "device_trusted": False,
        "network_trusted": False,
        "device_compliant": False,
        "device_posture_score": 20,
        "failed_login_attempts": 5,
        "unusual_activity": True,
        "session_age_minutes": 1500,
        "resource_sensitivity": "CRITICAL",
        "expected": "BLOCK"
    }
]


def api_request(path, method="GET", payload=None, token=None):
    headers = {"Content-Type": "application/json"}
    data = None

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
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        details = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"API error {error.code}: {details}")
    except urllib.error.URLError as error:
        raise RuntimeError(f"Backend connection failed: {error.reason}")


def main():
    print("\nSentinelAI Zero Trust Demo Seeder")
    print("---------------------------------")

    username = input("Admin username: ").strip()
    password = getpass.getpass("Admin password: ")

    login = api_request(
        "/api/auth/login",
        "POST",
        {"username": username, "password": password}
    )

    token = login["access_token"]
    print("\nAdmin authentication successful.")

    existing = api_request("/api/sessions", token=token)
    existing_sessions = existing.get("sessions", [])

    existing_users = {
        session.get("user")
        for session in existing_sessions
    }

    created = 0
    skipped = 0

    for scenario in SCENARIOS[:3]:
        user = scenario["user"]

        if user in existing_users:
            print(f"SKIPPED: {user} already has a session")
            skipped += 1
            continue

        payload = {
            key: value
            for key, value in scenario.items()
            if key != "expected"
        }

        result = api_request(
            "/api/sessions",
            "POST",
            payload,
            token
        )

        session = result.get("session", {})

        print(
            f"\nSESSION CREATED: {user}"
            f"\n  ID: {session.get('id')}"
            f"\n  Risk: {session.get('risk')}"
            f"\n  Decision: {session.get('decision')}"
            f"\n  Status: {session.get('status')}"
        )

        created += 1

    print("\nEvaluating high-risk BLOCK scenario...")

    block_scenario = SCENARIOS[3]
    block_payload = {
        key: value
        for key, value in block_scenario.items()
        if key != "expected"
    }

    block_result = api_request(
        "/api/zero-trust/check",
        "POST",
        block_payload
    )

    print(f"User: {block_scenario['user']}")
    print(f"Decision: {block_result.get('decision')}")
    print(f"Risk: {block_result.get('risk_score')}")
    print(f"Reason: {block_result.get('reason')}")

    print("\nRefreshing persistent session history...")

    verified = api_request("/api/sessions", token=token)
    sessions = verified.get("sessions", [])

    demo_sessions = [
        item for item in sessions
        if str(item.get("user", "")).startswith("DEMO_")
    ]

    print(f"Demo sessions visible: {len(demo_sessions)}")
    print(f"New sessions created: {created}")
    print(f"Existing sessions skipped: {skipped}")

    for item in demo_sessions:
        print(
            f"{item.get('user')} | "
            f"Risk: {item.get('risk')} | "
            f"Decision: {item.get('decision')} | "
            f"Status: {item.get('status')}"
        )

    print("\nZero Trust demo evaluation completed.")
    print("The BLOCK scenario was evaluated without creating a session.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"\nFAILED: {error}")
        raise SystemExit(1)
