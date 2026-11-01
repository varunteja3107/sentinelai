import json
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"

SCENARIOS = [
    {
        "threat_type": "BENIGN_TRAFFIC",
        "source_ip": "192.0.2.101",
        "destination_ip": "192.0.2.201",
        "protocol": "TCP",
        "port": 443,
        "packets": 20,
        "bytes_transferred": 12000
    },
    {
        "threat_type": "port_scan",
        "source_ip": "198.51.100.101",
        "destination_ip": "192.0.2.202",
        "protocol": "TCP",
        "port": 22,
        "packets": 300,
        "bytes_transferred": 18000
    },
    {
        "threat_type": "ddos",
        "source_ip": "198.51.100.102",
        "destination_ip": "192.0.2.203",
        "protocol": "TCP",
        "port": 443,
        "packets": 5000,
        "bytes_transferred": 5000000
    },
    {
        "threat_type": "dos",
        "source_ip": "198.51.100.103",
        "destination_ip": "192.0.2.204",
        "protocol": "TCP",
        "port": 80,
        "packets": 1500,
        "bytes_transferred": 1200000
    },
    {
        "threat_type": "brute_force",
        "source_ip": "198.51.100.104",
        "destination_ip": "192.0.2.205",
        "protocol": "TCP",
        "port": 22,
        "packets": 400,
        "bytes_transferred": 30000
    }
]


def request_api(path):
    request = urllib.request.Request(
        BASE_URL + path,
        headers={"Accept": "application/json"}
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        details = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"API error {error.code}: {details}")
    except urllib.error.URLError as error:
        raise RuntimeError(f"Backend connection failed: {error.reason}")


def post_threat(payload):
    data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        BASE_URL + "/api/threats/analyze",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        details = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"API error {error.code}: {details}")


def main():
    print("\nSentinelAI AI Threat Demo Seeder")
    print("--------------------------------")

    existing_data = request_api("/api/threats")

    if isinstance(existing_data, dict):
        existing_threats = existing_data.get(
            "threats",
            existing_data.get("items", [])
        )
    elif isinstance(existing_data, list):
        existing_threats = existing_data
    else:
        existing_threats = []

    existing_keys = {
        (item.get("threat_type"), item.get("source_ip"))
        for item in existing_threats
        if isinstance(item, dict)
    }

    created = 0
    skipped = 0
    failures = 0

    for scenario in SCENARIOS:
        key = (scenario["threat_type"], scenario["source_ip"])

        if key in existing_keys:
            print(
                f"SKIPPED: {scenario['threat_type']} "
                f"from {scenario['source_ip']} already exists"
            )
            skipped += 1
            continue

        try:
            result = post_threat(scenario)

            print(
                f"\nCREATED: {scenario['threat_type']}"
                f"\n  ID: {result.get('id')}"
                f"\n  Risk: {result.get('risk_score')}"
                f"\n  Severity: {result.get('severity')}"
                f"\n  Action: {result.get('action')}"
                f"\n  Anomaly score: {result.get('anomaly_score')}"
            )

            explanation = result.get("explanation")
            if explanation:
                print(f"  Model explanation: {explanation}")

            created += 1

        except Exception as error:
            print(f"\nFAILED: {scenario['threat_type']}: {error}")
            failures += 1

    print("\nDemo insertion summary")
    print("----------------------")
    print(f"Created: {created}")
    print(f"Skipped: {skipped}")
    print(f"Failed: {failures}")

    print("\nChecking incident and threat totals...")

    threats = request_api("/api/threats")
    incidents = request_api("/api/incidents")

    threat_count = (
        len(threats) if isinstance(threats, list)
        else threats.get("count", len(threats.get("threats", [])))
    )

    incident_count = (
        len(incidents) if isinstance(incidents, list)
        else incidents.get("count", len(incidents.get("incidents", [])))
    )

    print(f"Threat records returned: {threat_count}")
    print(f"Incident records returned: {incident_count}")

    if failures:
        print("\nSome scenarios failed. Review the errors above.")
    else:
        print("\nThreat demo batch completed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"\nSTOPPED: {error}")
        raise SystemExit(1)
