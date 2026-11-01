from pathlib import Path

path = Path("main.py")
source = path.read_text()

function_start = source.index("def evaluate_firewall(")
start = source.index("        matching_rules = sorted(", function_start)
end = source.index("\n\n    create_audit_log(", start)

replacement = '''        # Combine original default rules with persistent custom rules.
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
                and str(rule.get("protocol", "TCP")).upper()
                    in {"ANY", protocol}
                and source_matches(rule.get("source", "Any"), source_ip)
            ),
            key=lambda rule: (
                -int(rule.get("priority", 0)),
                int(rule.get("id", 0))
                + (1000000 if rule.get("custom") else 0),
            ),
        )

        matched = bool(matching_rules)
        rule = matching_rules[0] if matched else None
        action = rule["action"] if rule else "BLOCK"
        rule_name = rule["name"] if rule else "Default Deny Policy"
        priority = rule.get("priority", 0) if rule else 0

        matched_rule_type = (
            "CUSTOM" if rule and rule.get("custom")
            else "DEFAULT" if rule
            else "DEFAULT_DENY"
        )'''

source = source[:start] + replacement + source[end:]

old = '''        "priority": priority,
        "temporary_block": bool(forced_block_reason),'''

new = '''        "priority": priority,
        "rule_type": (
            "TEMPORARY_BLOCK" if forced_block_reason
            else matched_rule_type
        ),
        "monitor_only": action == "MONITOR",
        "temporary_block": bool(forced_block_reason),'''

if old not in source:
    raise SystemExit("Response block not found. No changes made.")

source = source.replace(old, new, 1)

path.write_text(source)
print("SUCCESS: Custom firewall rules connected to evaluator.")
