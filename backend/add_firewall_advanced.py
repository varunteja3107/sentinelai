from pathlib import Path
import shutil

path = Path("main.py")
source = path.read_text()

marker = "# SECURITY AUDIT LOGS"

if "def simulate_firewall_policy(" in source:
    print("Advanced firewall endpoints already exist. No changes made.")
    raise SystemExit(0)

if marker not in source:
    raise SystemExit("ERROR: Insertion point not found. No changes made.")

backup = Path("backups/feature_sprint/firewall_advanced")
backup.mkdir(parents=True, exist_ok=True)
shutil.copy2(path, backup / "main.py.before")

addition = r'''

# =========================================================
# ADVANCED FIREWALL: POLICY SIMULATOR AND RULE ANALYTICS
# =========================================================

@app.get("/api/firewall/simulate")
def simulate_firewall_policy(
    port: int,
    protocol: str = "TCP",
    source_ip: str | None = None,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    """Dry-run firewall policy evaluation without changing protection state."""

    if not 1 <= port <= 65535:
        raise HTTPException(status_code=422, detail="Port must be between 1 and 65535")

    protocol = protocol.strip().upper()
    if protocol not in {"TCP", "UDP"}:
        raise HTTPException(status_code=422, detail="Protocol must be TCP or UDP")

    if source_ip:
        source_ip = _valid_source_ip(source_ip)

    custom_rules = db.query(FirewallRule).all()

    custom_rule_dicts = [
        {
            "id": rule.id,
            "name": rule.name,
            "source": rule.source,
            "destination": rule.destination,
            "port": rule.port,
            "protocol": rule.protocol,
            "action": rule.action,
            "status": rule.status,
            "priority": rule.priority,
            "custom": True,
        }
        for rule in custom_rules
    ]

    all_rules = list(firewall_rules) + custom_rule_dicts

    matching_rules = sorted(
        (
            rule for rule in all_rules
            if rule.get("status") == "ACTIVE"
            and str(rule.get("port", "")) in {"*", str(port)}
            and str(rule.get("protocol", "TCP")).upper() in {"ANY", protocol}
            and source_matches(rule.get("source", "Any"), source_ip)
        ),
        key=lambda rule: (
            -int(rule.get("priority", 0)),
            int(rule.get("id", 0)) + (1000000 if rule.get("custom") else 0),
        ),
    )

    winner = matching_rules[0] if matching_rules else None
    action = winner["action"] if winner else "BLOCK"

    return {
        "simulation_only": True,
        "input": {
            "source_ip": source_ip,
            "port": port,
            "protocol": protocol,
        },
        "decision": action,
        "matched": winner is not None,
        "winning_rule": winner,
        "rule_type": (
            "CUSTOM" if winner and winner.get("custom")
            else "DEFAULT" if winner
            else "DEFAULT_DENY"
        ),
        "priority": winner.get("priority", 0) if winner else 0,
        "matching_rule_count": len(matching_rules),
        "matching_rules": matching_rules,
        "explanation": (
            f"Highest-priority matching rule '{winner['name']}' "
            f"selected action {action}."
            if winner else
            "No active rule matched. Default-deny policy selected BLOCK."
        ),
        "note": "This dry run does not modify firewall state or rate-limit counters.",
    }


@app.get("/api/firewall/analytics")
def firewall_rule_analytics(
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    """Summarize recorded firewall decisions from persistent audit logs."""

    logs = (
        db.query(AuditLog)
        .filter(AuditLog.event_type == "FIREWALL_DECISION")
        .order_by(AuditLog.id.desc())
        .limit(1000)
        .all()
    )

    action_counts = {"ALLOW": 0, "BLOCK": 0, "MONITOR": 0, "OTHER": 0}
    severity_counts = {}
    source_counts = {}
    rule_counts = {}

    for log in logs:
        action = (log.action or "").upper()
        if action in action_counts:
            action_counts[action] += 1
        else:
            action_counts["OTHER"] += 1

        severity = (log.severity or "UNKNOWN").upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        source = log.source_ip or "Unknown"
        source_counts[source] = source_counts.get(source, 0) + 1

        message = log.message or ""
        rule_name = "Unknown"
        for part in message.split(";"):
            if part.strip().startswith("Rule="):
                rule_name = part.strip()[5:]
                break
        rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1

    top_sources = sorted(
        [{"source_ip": k, "hits": v} for k, v in source_counts.items()],
        key=lambda item: item["hits"],
        reverse=True,
    )[:10]

    top_rules = sorted(
        [{"rule": k, "hits": v} for k, v in rule_counts.items()],
        key=lambda item: item["hits"],
        reverse=True,
    )[:10]

    return {
        "total_decisions": len(logs),
        "sample_limit": 1000,
        "actions": action_counts,
        "severities": severity_counts,
        "top_sources": top_sources,
        "top_rules": top_rules,
        "simulation_mode": True,
    }

'''

# AuditLog is imported immediately after the insertion marker.
# The endpoint functions resolve it when called, after module loading.
source = source.replace(marker, addition + "\n" + marker, 1)
path.write_text(source)

print("Added GET /api/firewall/simulate")
print("Added GET /api/firewall/analytics")
print("Backup saved.")
