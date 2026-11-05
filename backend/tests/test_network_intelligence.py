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


def test_historical_endpoint_correlation_detects_repeated_observations():
    from sentinel_x.network_intelligence import analyze_network_history

    observations = [
        {
            "connections": [{
                "remote_ip": "203.0.113.50",
                "remote_port": 8443,
                "protocol": "TCP",
            }],
        }
        for _ in range(5)
    ]

    result = analyze_network_history(observations)

    assert result["finding_count"] >= 1
    finding = next(
        item for item in result["findings"]
        if item["type"] == "historical_endpoint_recurrence"
    )
    assert finding["observation_count"] == 5


def test_historical_analysis_does_not_flag_one_normal_https_observation():
    from sentinel_x.network_intelligence import analyze_network_history

    result = analyze_network_history([{
        "connections": [{
            "remote_ip": "203.0.113.60",
            "remote_port": 443,
            "protocol": "TCP",
        }],
    }])

    assert result["finding_count"] == 0


def test_historical_analysis_ignores_duplicate_entries_within_one_snapshot():
    from sentinel_x.network_intelligence import analyze_network_history

    observations = [{
        "connections": [
            {
                "remote_ip": "203.0.113.70",
                "remote_port": 8443,
                "protocol": "TCP",
            }
        ] * 20,
    }]

    result = analyze_network_history(observations)

    assert not any(
        item["type"] == "historical_endpoint_recurrence"
        for item in result["findings"]
    )


def test_historical_endpoint_is_not_active_when_absent_from_latest_snapshot():
    from sentinel_x.network_intelligence import analyze_network_history

    endpoint = {
        "remote_ip": "203.0.113.80",
        "remote_port": 8443,
        "protocol": "TCP",
    }

    observations = [
        {"connections": [endpoint]}
        for _ in range(4)
    ]
    observations.append({"connections": []})

    result = analyze_network_history(observations)

    assert result["finding_count"] == 0


def test_historical_analysis_excludes_loopback_addresses():
    from sentinel_x.network_intelligence import analyze_network_history

    observations = [
        {
            "connections": [
                {"remote_ip": "127.0.0.1", "remote_port": 8000, "protocol": "TCP"},
                {"remote_ip": "::1", "remote_port": 5173, "protocol": "TCP"},
                {"remote_ip": "127.0.0.2", "remote_port": 9000, "protocol": "TCP"},
            ],
        }
        for _ in range(5)
    ]

    result = analyze_network_history(observations)

    assert result["finding_count"] == 0
    assert result["risk_score"] == 0


def test_recurring_https_is_low_contextual_evidence():
    from sentinel_x.network_intelligence import analyze_network_history

    observations = [
        {
            "connections": [
                {"remote_ip": "203.0.113.60", "remote_port": 443, "protocol": "TCP"},
            ],
        }
        for _ in range(5)
    ]

    result = analyze_network_history(observations)

    assert result["finding_count"] == 1
    assert result["risk_score"] == 0
    assert result["severity"] == "LOW"
    assert result["findings"][0]["severity"] == "LOW"
    assert result["findings"][0]["risk_score"] == 5


def test_multi_port_scan_indicator_detects_many_ports_on_one_ip():
    connections = [
        {
            "remote_ip": "203.0.113.100",
            "remote_port": port,
            "protocol": "TCP",
        }
        for port in range(1000, 1015)
    ]

    result = analyze_network_observation({"connections": connections})

    finding = next(
        (
            item for item in result["findings"]
            if item["type"] == "multi_port_scan_indicator"
        ),
        None,
    )
    assert finding is not None
    assert finding["distinct_ports"] == 15


def test_multi_port_scan_below_threshold_is_not_flagged():
    connections = [
        {
            "remote_ip": "203.0.113.100",
            "remote_port": port,
            "protocol": "TCP",
        }
        for port in range(1000, 1014)
    ]

    result = analyze_network_observation({"connections": connections})

    assert not any(
        item["type"] == "multi_port_scan_indicator"
        for item in result["findings"]
    )


def test_ports_across_different_ips_are_not_combined():
    connections = [
        {
            "remote_ip": f"203.0.113.{index}",
            "remote_port": 1000 + index,
            "protocol": "TCP",
        }
        for index in range(1, 16)
    ]

    result = analyze_network_observation({"connections": connections})

    assert not any(
        item["type"] == "multi_port_scan_indicator"
        for item in result["findings"]
    )


def test_multi_port_scan_ignores_invalid_connections():
    connections = [
        {"remote_ip": "invalid-ip", "remote_port": port, "protocol": "TCP"}
        for port in range(1000, 1020)
    ]

    result = analyze_network_observation({"connections": connections})

    assert not any(
        item["type"] == "multi_port_scan_indicator"
        for item in result["findings"]
    )


def test_connection_volume_spike_detected_with_recent_baseline():
    from datetime import datetime, timedelta

    now = datetime.utcnow()
    observations = [
        {
            "captured_at": now - timedelta(seconds=offset),
            "connections": [{"remote_ip": "203.0.113.10", "remote_port": 443}]
            * 10,
        }
        for offset in (120, 90, 60, 30)
    ]
    observations.append({
        "captured_at": now,
        "connections": [
            {"remote_ip": "203.0.113.10", "remote_port": 443}
        ] * 50,
    })

    from sentinel_x.network_intelligence import analyze_network_history
    result = analyze_network_history(observations)

    assert any(
        item["type"] == "connection_volume_spike"
        for item in result["findings"]
    )


def test_normal_connection_growth_is_not_flagged():
    from datetime import datetime, timedelta
    from sentinel_x.network_intelligence import analyze_network_history

    now = datetime.utcnow()
    observations = [
        {
            "captured_at": now - timedelta(seconds=offset),
            "connections": [{"remote_ip": "203.0.113.10", "remote_port": 443}]
            * 20,
        }
        for offset in (120, 90, 60, 30)
    ]
    observations.append({
        "captured_at": now,
        "connections": [
            {"remote_ip": "203.0.113.10", "remote_port": 443}
        ] * 35,
    })

    result = analyze_network_history(observations)

    assert not any(
        item["type"] == "connection_volume_spike"
        for item in result["findings"]
    )


def test_connection_volume_spike_requires_enough_recent_history():
    from datetime import datetime, timedelta
    from sentinel_x.network_intelligence import analyze_network_history

    now = datetime.utcnow()
    observations = [
        {
            "captured_at": now - timedelta(seconds=30),
            "connections": [{"remote_ip": "203.0.113.10", "remote_port": 443}] * 10,
        },
        {
            "captured_at": now,
            "connections": [{"remote_ip": "203.0.113.10", "remote_port": 443}] * 60,
        },
    ]

    result = analyze_network_history(observations)

    assert not any(
        item["type"] == "connection_volume_spike"
        for item in result["findings"]
    )


def test_connection_volume_spike_ignores_stale_baseline():
    from datetime import datetime, timedelta
    from sentinel_x.network_intelligence import analyze_network_history

    now = datetime.utcnow()
    observations = [
        {
            "captured_at": now - timedelta(seconds=offset),
            "connections": [{"remote_ip": "203.0.113.10", "remote_port": 443}] * 10,
        }
        for offset in (900, 600, 300, 30)
    ]
    observations.append({
        "captured_at": now,
        "connections": [{"remote_ip": "203.0.113.10", "remote_port": 443}] * 60,
    })

    result = analyze_network_history(observations)

    assert not any(
        item["type"] == "connection_volume_spike"
        for item in result["findings"]
    )
