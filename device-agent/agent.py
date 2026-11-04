#!/usr/bin/env python3
"""SentinelAI Mac health agent. Sends health metrics only; location is separate and opt-in in the web UI."""
import os
import platform
import re
import socket
import time
from datetime import datetime, timezone

import psutil
import requests

API = os.environ.get("SENTINELAI_API_URL", "https://sentinelai-api-2pqw.onrender.com").rstrip("/")
DEVICE_TOKEN = os.environ.get("SENTINELAI_DEVICE_TOKEN", "").strip()
LEGACY_TOKEN = os.environ.get("DEVICE_MONITOR_TOKEN", "").strip()
TOKEN = DEVICE_TOKEN or LEGACY_TOKEN
INTERVAL_SECONDS = int(os.environ.get("SENTINELAI_MONITOR_INTERVAL", "15"))

if not TOKEN:
    raise SystemExit("DEVICE_MONITOR_TOKEN is missing. Run install_agent.py and configure the token in Render first.")


def local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return "unavailable"
    finally:
        sock.close()


def battery_info():
    try:
        batt = psutil.sensors_battery()
        if batt is not None:
            return round(batt.percent, 1), bool(batt.power_plugged)
    except Exception:
        pass
    # macOS fallback if psutil can't read battery information.
    try:
        import subprocess
        out = subprocess.run(["pmset", "-g", "batt"], capture_output=True, text=True, timeout=3).stdout
        match = re.search(r"(\d+)%", out)
        charging = "AC Power" in out or "charging" in out.lower()
        return (float(match.group(1)) if match else None), charging
    except Exception:
        return None, None


def stable_device_id():
    name = socket.gethostname().strip() or "sentinelai-mac"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")[:100]
    return safe or "sentinelai-mac"


def collect():
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    battery_percent, plugged = battery_info()
    name = socket.gethostname() or "Mac laptop"
    return {
        "device_id": stable_device_id(),
        "device_name": name,
        "platform": platform.system(),
        "os_version": platform.mac_ver()[0] or platform.release(),
        "cpu_percent": round(psutil.cpu_percent(interval=1), 1),
        "cpu_cores": psutil.cpu_count(logical=True),
        "memory_percent": round(vm.percent, 1),
        "memory_used_gb": round(vm.used / (1024 ** 3), 2),
        "memory_total_gb": round(vm.total / (1024 ** 3), 2),
        "disk_percent": round(disk.percent, 1),
        "battery_percent": battery_percent,
        "battery_power_plugged": plugged,
        "local_ip": local_ip(),
        "network_sent_mb": round(net.bytes_sent / (1024 ** 2), 2) if net else None,
        "network_recv_mb": round(net.bytes_recv / (1024 ** 2), 2) if net else None,
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }



NETWORK_INTERVAL_SECONDS = 30
MAX_NETWORK_CONNECTIONS = 100




def collect_network():
    """Collect socket metadata using native lsof on macOS."""
    import ipaddress
    import subprocess

    connections = []
    warnings = []
    restricted_processes = 0

    def parse_endpoint(value):
        if not value:
            return None, None

        if value.startswith("["):
            closing = value.find("]")
            if closing < 0:
                return None, None
            host = value[1:closing]
            suffix = value[closing + 1:]
            port_text = suffix[1:] if suffix.startswith(":") else ""
        else:
            host, separator, port_text = value.rpartition(":")
            if not separator:
                return None, None

        if host in ("", "*"):
            host = None
        elif host:
            try:
                host = str(ipaddress.ip_address(host))
            except ValueError:
                return None, None

        try:
            port = int(port_text) if port_text and port_text != "*" else None
        except ValueError:
            port = None

        if port is not None and not 0 <= port <= 65535:
            port = None

        return host, port

    if platform.system() == "Darwin":
        try:
            result = subprocess.run(
                [
                    "/usr/sbin/lsof",
                    "-nP",
                    "-iTCP",
                    "-iUDP",
                    "-FpfPnT",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.stderr.strip():
                warning_text = result.stderr.lower()
                if any(word in warning_text for word in (
                    "permission denied", "operation not permitted", "access denied"
                )):
                    restricted_processes = 1
                warnings.append(
                    "lsof reported partial visibility or collection warnings."
                )

            current_pid = None
            current_record = None

            def save_record(record):
                if not record or len(connections) >= MAX_NETWORK_CONNECTIONS:
                    return

                local_ip = record.get("local_ip")
                remote_ip = record.get("remote_ip")

                if not local_ip and not remote_ip:
                    return

                connections.append({
                    "local_ip": local_ip,
                    "local_port": record.get("local_port"),
                    "remote_ip": remote_ip,
                    "remote_port": record.get("remote_port"),
                    "protocol": record.get("protocol", "OTHER"),
                    "status": record.get("status", "UNKNOWN"),
                    "pid": record.get("pid"),
                })

            for line in result.stdout.splitlines():
                if line.startswith("p"):
                    save_record(current_record)
                    current_record = None
                    try:
                        current_pid = int(line[1:])
                    except ValueError:
                        current_pid = None

                elif line.startswith("f"):
                    save_record(current_record)
                    current_record = {
                        "pid": current_pid,
                        "protocol": "OTHER",
                        "status": "UNKNOWN",
                        "local_ip": None,
                        "local_port": None,
                        "remote_ip": None,
                        "remote_port": None,
                    }

                elif current_record is not None and line.startswith("P"):
                    protocol = line[1:].upper()
                    current_record["protocol"] = (
                        protocol if protocol in ("TCP", "UDP") else "OTHER"
                    )

                elif current_record is not None and line.startswith("n"):
                    address = line[1:]
                    if "->" in address:
                        local, remote = address.split("->", 1)
                    else:
                        local, remote = address, None

                    current_record["local_ip"], current_record["local_port"] = (
                        parse_endpoint(local)
                    )

                    if remote:
                        current_record["remote_ip"], current_record["remote_port"] = (
                            parse_endpoint(remote)
                        )

                elif current_record is not None and line.startswith("TST="):
                    current_record["status"] = line[4:][:32]

            save_record(current_record)

            if result.returncode != 0 and not connections:
                warnings.append(
                    f"lsof returned exit code {result.returncode}."
                )

            if len(connections) >= MAX_NETWORK_CONNECTIONS:
                warnings.append(
                    f"Connection collection capped at {MAX_NETWORK_CONNECTIONS}."
                )

        except subprocess.TimeoutExpired:
            warnings.append("lsof network collection timed out.")
        except FileNotFoundError:
            warnings.append("Native lsof command is unavailable.")
        except Exception as exc:
            warnings.append(
                f"Native network collection failed: {type(exc).__name__}"
            )

    else:
        try:
            for conn in psutil.net_connections(kind="inet"):
                if len(connections) >= MAX_NETWORK_CONNECTIONS:
                    warnings.append(
                        f"Connection collection capped at {MAX_NETWORK_CONNECTIONS}."
                    )
                    break

                local = conn.laddr
                remote = conn.raddr

                if not local and not remote:
                    continue

                connections.append({
                    "local_ip": local.ip if local else None,
                    "local_port": local.port if local else None,
                    "remote_ip": remote.ip if remote else None,
                    "remote_port": remote.port if remote else None,
                    "status": conn.status or "UNKNOWN",
                    "protocol": (
                        "TCP" if conn.type == socket.SOCK_STREAM
                        else "UDP" if conn.type == socket.SOCK_DGRAM
                        else "OTHER"
                    ),
                    "pid": conn.pid,
                })

        except psutil.AccessDenied:
            restricted_processes = 1
            warnings.append("Operating system restricted socket visibility.")
        except Exception as exc:
            warnings.append(
                f"Network collection unavailable: {type(exc).__name__}"
            )

    return {
        "device_id": stable_device_id(),
        "connections": connections[:MAX_NETWORK_CONNECTIONS],
        "restricted_processes": restricted_processes,
        "warnings": warnings,
    }


def main():
    headers = {"Authorization": f"Bearer {TOKEN}"}
    endpoint = f"{API}/api/device-monitor/report"
    network_endpoint = f"{API}/api/x/telemetry/network"

    last_network_report = 0.0

    print(
        f"SentinelAI device agent started for {socket.gethostname()}. "
        f"Health interval: {INTERVAL_SECONDS}s; "
        f"network interval: {NETWORK_INTERVAL_SECONDS}s.",
        flush=True,
    )
    print(
        "Health and connection metadata are shared. "
        "Packet contents and physical location are not collected.",
        flush=True,
    )

    while True:
        try:
            report = collect()
            response = requests.post(
                endpoint, json=report, headers=headers, timeout=12
            )

            if response.ok:
                print(
                    f"[{datetime.now().isoformat(timespec='seconds')}] "
                    f"Health report sent. CPU={report['cpu_percent']}% "
                    f"RAM={report['memory_percent']}%",
                    flush=True,
                )
            else:
                print(
                    f"Health API error {response.status_code}: "
                    f"{response.text[:300]}",
                    flush=True,
                )

            now = time.monotonic()
            if now - last_network_report >= NETWORK_INTERVAL_SECONDS:
                network_report = collect_network()
                network_response = requests.post(
                    network_endpoint,
                    json=network_report,
                    headers=headers,
                    timeout=12,
                )

                if network_response.ok:
                    result = network_response.json()
                    print(
                        f"[{datetime.now().isoformat(timespec='seconds')}] "
                        f"Network report sent. "
                        f"Connections={result.get('connection_count', 0)} "
                        f"Restricted={network_report['restricted_processes']}",
                        flush=True,
                    )
                else:
                    print(
                        f"Network API error {network_response.status_code}: "
                        f"{network_response.text[:300]}",
                        flush=True,
                    )

                last_network_report = now

        except Exception as exc:
            print(f"Agent error: {exc}", flush=True)

        time.sleep(max(10, INTERVAL_SECONDS))


if __name__ == "__main__":
    main()
