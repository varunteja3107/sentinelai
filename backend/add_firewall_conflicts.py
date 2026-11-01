from pathlib import Path

path = Path("main.py")
source = path.read_text()

marker = '@app.get("/api/firewall/rules")'

if 'def firewall_rule_conflicts(' in source:
    raise SystemExit("Conflict detection already exists. No changes made.")

if marker not in source:
    raise SystemExit("Could not find rule listing endpoint. No changes made.")

code = r'''
# FIREWALL RULE CONFLICT DETECTION
# Compares default and custom rules without changing enforcement.

def _conflict_source_overlap(source_a, source_b):
    import ipaddress

    a = str(source_a or "Any").strip()
    b = str(source_b or "Any").strip()

    if a.lower() == "any" or b.lower() == "any":
        return True, False

    try:
        net_a = ipaddress.ip_network(a, strict=False)
        net_b = ipaddress.ip_network(b, strict=False)

        if net_a.version != net_b.version:
            return False, False

        return net_a.overlaps(net_b), False
    except ValueError:
        # Legacy labels such as "Internal Network" are not CIDRs.
        # Conservatively report possible overlap, not confirmed overlap.
        return True, True


def _conflict_port_overlap(port_a, port_b):
    a = str(port_a or "*").strip()
    b = str(port_b or "*").strip()
    return a == "*" or b == "*" or a == b


def _conflict_protocol_overlap(protocol_a, protocol_b):
    a = str(protocol_a or "TCP").upper()
    b = str(protocol_b or "TCP").upper()
    return a == "ANY" or b == "ANY" or a == b


def _conflict_rule_view(rule):
    return {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "source": rule.get("source", "Any"),
        "destination": rule.get("destination", "Any"),
        "port": str(rule.get("port", "*")),
        "protocol": str(rule.get("protocol", "TCP")).upper(),
        "action": str(rule.get("action", "BLOCK")).upper(),
        "status": str(rule.get("status", "ACTIVE")).upper(),
        "priority": int(rule.get("priority", 0)),
        "custom": bool(rule.get("custom", False)),
    }


@app.get("/api/firewall/rules/conflicts")
def firewall_rule_conflicts(
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    custom_rules = db.query(FirewallRule).all()

    all_rules = [
        _conflict_rule_view({**rule, "custom": False})
        for rule in firewall_rules
    ]

    all_rules.extend(
        _conflict_rule_view(serialize_custom_firewall_rule(rule))
        for rule in custom_rules
    )

    active_rules = [
        rule for rule in all_rules if rule["status"] == "ACTIVE"
    ]

    findings = []

    for index, first in enumerate(active_rules):
        for second in active_rules[index + 1:]:
            source_overlap, uncertain_source = _conflict_source_overlap(
                first["source"], second["source"]
            )

            if not source_overlap:
                continue

            if not _conflict_port_overlap(first["port"], second["port"]):
                continue

            if not _conflict_protocol_overlap(
                first["protocol"], second["protocol"]
            ):
                continue

            same_action = first["action"] == second["action"]

            exact_match = (
                first["source"].strip().lower()
                == second["source"].strip().lower()
                and first["port"] == second["port"]
                and first["protocol"] == second["protocol"]
            )

            if same_action and exact_match:
                conflict_type = "DUPLICATE"
                severity = "LOW"
                message = "Rules have identical matching conditions and actions."
            elif not same_action:
                conflict_type = "ACTION_CONFLICT"
                severity = "HIGH"
                message = (
                    f"Overlapping rules use different actions: "
                    f"{first['action']} and {second['action']}."
                )
            else:
                conflict_type = "OVERLAP"
                severity = "MEDIUM"
                message = "Rules overlap and may both match the same traffic."

            if uncertain_source:
                severity = "MEDIUM" if severity == "LOW" else severity
                message += (
                    " Source scope uses a descriptive label, so overlap "
                    "is conservative and requires manual verification."
                )

            destination_note = None
            if first["destination"] != second["destination"]:
                destination_note = (
                    "Destination values differ, but destination matching "
                    "is not currently enforced by the traffic evaluator."
                )

            findings.append({
                "type": conflict_type,
                "severity": severity,
                "message": message,
                "rule_a": first,
                "rule_b": second,
                "same_priority": first["priority"] == second["priority"],
                "destination_note": destination_note,
                "source_overlap_uncertain": uncertain_source,
            })

    return {
        "total_rules": len(all_rules),
        "active_rules": len(active_rules),
        "disabled_rules": len(all_rules) - len(active_rules),
        "conflict_count": len(findings),
        "high_severity": sum(
            item["severity"] == "HIGH" for item in findings
        ),
        "medium_severity": sum(
            item["severity"] == "MEDIUM" for item in findings
        ),
        "low_severity": sum(
            item["severity"] == "LOW" for item in findings
        ),
        "conflicts": findings,
        "simulation_only": True,
    }


'''

path.write_text(source.replace(marker, code + marker, 1))
print("Firewall conflict detection endpoint added.")
