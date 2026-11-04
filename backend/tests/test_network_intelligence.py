from sentinel_x.network_intelligence import analyze_network_observation


def test_empty_observation_has_no_findings():
    result = analyze_network_observation({
        "connections": [],
        "restricted_processes": 0,
        "warnings": [],
    })

    assert result["risk_score"] == 0
    assert result["finding_count"] == 0
    assert result["severity"] == "LOW"


def test_repeated_remote_endpoint_is_detected():
    connections = [
        {
            "remote_ip": "203.0.113.10",
            "remote_port": 443,
            "protocol": "TCP",
        }
        for _ in range(12)
    ]

    result = analyze_network_observation({"connections": connections})

    assert result["risk_score"] == 25
    assert result["severity"] == "MEDIUM"
    assert result["findings"][0]["type"] == "repeated_remote_endpoint"


def test_sensitive_remote_port_is_flagged_for_review():
    result = analyze_network_observation({
        "connections": [{
            "remote_ip": "203.0.113.20",
            "remote_port": 3389,
            "protocol": "TCP",
        }]
    })

    assert result["risk_score"] == 10
    assert result["severity"] == "LOW"
    assert result["findings"][0]["service"] == "Remote Desktop"


def test_restricted_process_indicator_increases_risk():
    result = analyze_network_observation({
        "connections": [],
        "restricted_processes": 2,
    })

    assert result["risk_score"] == 35
    assert result["severity"] == "MEDIUM"
    assert result["findings"][0]["type"] == "restricted_process_indicator"


def test_risk_score_is_capped_at_100():
    connections = [
        {
            "remote_ip": "203.0.113.30",
            "remote_port": 445,
            "protocol": "TCP",
        }
        for _ in range(100)
    ]

    result = analyze_network_observation({
        "connections": connections,
        "restricted_processes": 100,
    })

    assert result["risk_score"] <= 100


def test_invalid_connection_entries_are_ignored():
    result = analyze_network_observation({
        "connections": [None, "invalid", {}],
        "restricted_processes": 0,
    })

    assert result["connection_count"] == 3
    assert result["finding_count"] == 0
    assert result["risk_score"] == 0
