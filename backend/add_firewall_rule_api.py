from pathlib import Path

path = Path("main.py")
source = path.read_text()

marker = "# FIREWALL RULES"

if "def create_custom_firewall_rule" in source:
    raise SystemExit("Firewall CRUD endpoints already exist. No changes made.")

if marker not in source:
    raise SystemExit("Firewall section not found. No changes made.")

block = '''

# CUSTOM FIREWALL RULE MANAGEMENT
# Database-backed rules created through the Firewall Rule Builder.

class FirewallRuleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    source: str = Field(default="Any", max_length=128)
    destination: str = Field(default="Any", max_length=128)
    port: str = Field(min_length=1, max_length=32)
    protocol: str = Field(default="TCP", max_length=16)
    action: str = Field(default="BLOCK", max_length=16)
    priority: int = Field(default=50, ge=1, le=1000)
    description: str = Field(default="", max_length=500)


class FirewallRuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=128)
    source: Optional[str] = Field(default=None, max_length=128)
    destination: Optional[str] = Field(default=None, max_length=128)
    port: Optional[str] = Field(default=None, max_length=32)
    protocol: Optional[str] = Field(default=None, max_length=16)
    action: Optional[str] = Field(default=None, max_length=16)
    priority: Optional[int] = Field(default=None, ge=1, le=1000)
    description: Optional[str] = Field(default=None, max_length=500)


def serialize_custom_firewall_rule(rule):
    return {
        "id": rule.id,
        "name": rule.name,
        "source": rule.source,
        "destination": rule.destination,
        "port": rule.port,
        "protocol": rule.protocol,
        "action": rule.action,
        "status": rule.status,
        "priority": rule.priority,
        "description": rule.description or "",
        "custom": True,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }


def validate_firewall_rule_values(values):
    import ipaddress

    protocol = str(values.get("protocol", "TCP")).upper()
    action = str(values.get("action", "BLOCK")).upper()
    port = str(values.get("port", "")).strip()
    source_ip = str(values.get("source", "Any")).strip()

    if protocol not in {"TCP", "UDP", "ICMP", "ANY"}:
        raise HTTPException(status_code=422, detail="Protocol must be TCP, UDP, ICMP or ANY.")

    if action not in {"ALLOW", "BLOCK", "MONITOR"}:
        raise HTTPException(status_code=422, detail="Action must be ALLOW, BLOCK or MONITOR.")

    if port != "*":
        try:
            port_number = int(port)
            if not 1 <= port_number <= 65535:
                raise ValueError
        except ValueError:
            raise HTTPException(status_code=422, detail="Port must be * or a number from 1 to 65535.")

    if source_ip.lower() != "any":
        try:
            ipaddress.ip_network(source_ip, strict=False)
        except ValueError:
            raise HTTPException(status_code=422, detail="Source must be Any, an IP address or a CIDR range.")

    values["protocol"] = protocol
    values["action"] = action
    values["port"] = port
    values["source"] = source_ip


@app.post("/api/firewall/rules")
def create_custom_firewall_rule(
    payload: FirewallRuleCreate,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    values = payload.model_dump()
    validate_firewall_rule_values(values)

    rule = FirewallRule(
        **values,
        status="ACTIVE",
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return serialize_custom_firewall_rule(rule)


@app.put("/api/firewall/rules/{rule_id}")
def update_custom_firewall_rule(
    rule_id: int,
    payload: FirewallRuleUpdate,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Custom firewall rule not found.")

    values = payload.model_dump(exclude_unset=True)
    validate_firewall_rule_values({
        "source": values.get("source", rule.source),
        "port": values.get("port", rule.port),
        "protocol": values.get("protocol", rule.protocol),
        "action": values.get("action", rule.action),
    })

    for key, value in values.items():
        if value is not None:
            setattr(rule, key, value)

    rule.protocol = rule.protocol.upper()
    rule.action = rule.action.upper()
    rule.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(rule)
    return serialize_custom_firewall_rule(rule)


@app.post("/api/firewall/rules/{rule_id}/status")
def set_custom_firewall_rule_status(
    rule_id: int,
    enabled: bool,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Custom firewall rule not found.")

    rule.status = "ACTIVE" if enabled else "DISABLED"
    rule.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(rule)
    return serialize_custom_firewall_rule(rule)


@app.delete("/api/firewall/rules/{rule_id}")
def delete_custom_firewall_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Custom firewall rule not found.")

    db.delete(rule)
    db.commit()
    return {"message": "Custom firewall rule deleted.", "id": rule_id}

'''

source = source.replace(marker, block + "\n" + marker, 1)
path.write_text(source)
print("SUCCESS: Custom firewall rule API endpoints added.")
