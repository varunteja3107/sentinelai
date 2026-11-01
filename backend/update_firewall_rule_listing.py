from pathlib import Path

path = Path("main.py")
source = path.read_text()

old = '''@app.get("/api/firewall/rules")
def get_firewall_rules():
    return sorted(
        firewall_rules,
        key=lambda rule: (-rule.get("priority", 0), rule["id"]),
    )
'''

new = '''@app.get("/api/firewall/rules")
def get_firewall_rules(db: Session = Depends(get_db)):
    custom_rules = db.query(FirewallRule).all()

    default_rules = [
        {**rule, "custom": False}
        for rule in firewall_rules
    ]

    persistent_rules = [
        serialize_custom_firewall_rule(rule)
        for rule in custom_rules
    ]

    return sorted(
        default_rules + persistent_rules,
        key=lambda rule: (
            -int(rule.get("priority", 0)),
            int(rule["id"]) + (1000000 if rule.get("custom") else 0),
        ),
    )
'''

if old not in source:
    raise SystemExit("Existing listing function did not match. No changes made.")

source = source.replace(old, new, 1)
path.write_text(source)
print("SUCCESS: Rule listing now includes default and custom rules.")
