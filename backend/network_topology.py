import ipaddress
from datetime import datetime

import psutil
from fastapi import APIRouter
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Device, Threat

router = APIRouter(tags=["Network Topology"])


def valid_ip(value):
    if not value:
        return False

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_interfaces():
    interfaces = []
    interface_stats = psutil.net_if_stats()
    interface_addresses = psutil.net_if_addrs()

    for interface_name, addresses in interface_addresses.items():
        stats = interface_stats.get(interface_name)
        ips = []

        for address in addresses:
            if address.family == 2:
                family = "IPv4"
            elif address.family == 30:
                family = "IPv6"
            else:
                continue

            if not valid_ip(address.address):
                continue

            item = {
                "address": address.address,
                "family": family,
                "netmask": address.netmask,
            }

            if address.netmask and family == "IPv4":
                try:
                    network = ipaddress.ip_interface(
                        f"{address.address}/{address.netmask}"
                    ).network
                    item["subnet"] = str(network)
                except ValueError:
                    item["subnet"] = None

            ips.append(item)

        if ips:
            interfaces.append({
                "name": interface_name,
                "is_up": bool(stats.isup) if stats else None,
                "speed_mbps": stats.speed if stats else None,
                "addresses": ips,
            })

    return interfaces


def get_connection_data():
    connections = []
    warnings = []
    restricted_processes = 0

    for process in psutil.process_iter(["pid"]):
        try:
            for connection in process.connections(kind="inet"):
                local = connection.laddr
                remote = connection.raddr

                if not local and not remote:
                    continue

                connections.append({
                    "local_ip": local.ip if local else None,
                    "local_port": local.port if local else None,
                    "remote_ip": remote.ip if remote else None,
                    "remote_port": remote.port if remote else None,
                    "status": connection.status,
                    "protocol": (
                        "TCP" if connection.type == 1
                        else "UDP" if connection.type == 2
                        else "OTHER"
                    ),
                    "pid": process.pid,
                })

        except psutil.AccessDenied:
            restricted_processes += 1
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except OSError:
            restricted_processes += 1

    if restricted_processes:
        warnings.append(
            f"Partial connection visibility: macOS restricted "
            f"{restricted_processes} process(es). "
            f"{len(connections)} visible connection(s) collected."
        )

    return connections, warnings


@router.get("/api/network/topology")
def network_topology():
    db: Session = SessionLocal()

    try:
        interfaces = get_interfaces()
        connections, warnings = get_connection_data()

        device_records = db.query(Device).all()
        threat_records = db.query(Threat).order_by(
            Threat.created_at.desc()
        ).limit(500).all()

        nodes = {}
        edges = {}

        def add_node(ip, source, name=None):
            if not valid_ip(ip):
                return

            if ip not in nodes:
                try:
                    parsed = ipaddress.ip_address(ip)
                    address_type = (
                        "private" if parsed.is_private
                        else "loopback" if parsed.is_loopback
                        else "public"
                    )
                except ValueError:
                    address_type = "unknown"

                nodes[ip] = {
                    "id": ip,
                    "ip_address": ip,
                    "name": name or ip,
                    "address_type": address_type,
                    "sources": [],
                    "connection_count": 0,
                    "threat_count": 0,
                    "max_risk_score": 0,
                    "highest_severity": "NONE",
                }

            if source not in nodes[ip]["sources"]:
                nodes[ip]["sources"].append(source)

            if name and nodes[ip]["name"] == ip:
                nodes[ip]["name"] = name

        local_ips = set()

        for interface in interfaces:
            for address in interface["addresses"]:
                ip = address["address"]
                local_ips.add(ip)
                add_node(ip, "LOCAL_INTERFACE", interface["name"])

        for device in device_records:
            add_node(
                device.ip_address,
                "DEVICE_DATABASE",
                device.name,
            )

        for connection in connections:
            local_ip = connection["local_ip"]
            remote_ip = connection["remote_ip"]

            add_node(local_ip, "OBSERVED_CONNECTION")
            add_node(remote_ip, "OBSERVED_CONNECTION")

            if local_ip and remote_ip:
                edge_id = (
                    f'{local_ip}:{connection["local_port"]}'
                    f'->{remote_ip}:{connection["remote_port"]}'
                )

                edges[edge_id] = {
                    "id": edge_id,
                    "source": local_ip,
                    "target": remote_ip,
                    "source_port": connection["local_port"],
                    "target_port": connection["remote_port"],
                    "protocol": connection["protocol"],
                    "status": connection["status"],
                }

                nodes[local_ip]["connection_count"] += 1
                nodes[remote_ip]["connection_count"] += 1

        severity_rank = {
            "NONE": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        threat_events = []

        for threat in threat_records:
            source_ip = threat.source_ip
            destination_ip = threat.destination_ip

            add_node(source_ip, "THREAT_DATABASE")
            add_node(destination_ip, "THREAT_DATABASE")

            severity = str(threat.severity or "LOW").upper()
            risk = float(threat.risk_score or 0)

            for ip in (source_ip, destination_ip):
                if valid_ip(ip):
                    node = nodes[ip]
                    node["threat_count"] += 1
                    node["max_risk_score"] = max(
                        node["max_risk_score"], risk
                    )

                    if severity_rank.get(severity, 0) > severity_rank.get(
                        node["highest_severity"], 0
                    ):
                        node["highest_severity"] = severity

            threat_events.append({
                "id": threat.id,
                "threat_type": threat.threat_type,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "protocol": threat.protocol,
                "port": threat.port,
                "risk_score": risk,
                "severity": severity,
                "action": threat.action,
                "status": threat.status,
                "created_at": (
                    threat.created_at.isoformat()
                    if isinstance(threat.created_at, datetime)
                    else None
                ),
            })

        node_list = list(nodes.values())

        return {
            "generated_at": datetime.now().astimezone().isoformat(),
            "discovery_mode": "READ_ONLY",
            "interfaces": interfaces,
            "nodes": node_list,
            "edges": list(edges.values()),
            "threats": threat_events,
            "statistics": {
                "interface_count": len(interfaces),
                "local_ip_count": len(local_ips),
                "node_count": len(node_list),
                "connection_count": len(edges),
                "threat_event_count": len(threat_events),
                "suspicious_node_count": sum(
                    1 for node in node_list if node["threat_count"] > 0
                ),
            },
            "warnings": warnings,
            "data_notes": [
                "Local interfaces are discovered from the backend host.",
                "Connections are those visible to the backend process.",
                "Database devices are known records, not proof of current reachability.",
                "Threat indicators are correlated from recorded database events.",
                "This endpoint does not actively scan the network.",
            ],
        }

    finally:
        db.close()
