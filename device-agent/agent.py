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

API = os.environ.get("SENTINELAI_API_URL", "https://sentinelai-wnno.onrender.com").rstrip("/")
TOKEN = os.environ.get("DEVICE_MONITOR_TOKEN", "").strip()
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


def main():
    headers = {"Authorization": f"Bearer {TOKEN}"}
    endpoint = f"{API}/api/device-monitor/report"
    print(f"SentinelAI device agent started for {socket.gethostname()}. Interval: {INTERVAL_SECONDS}s.", flush=True)
    print("Health metrics are shared; physical location remains off until enabled from Device Monitor in a browser on this Mac.", flush=True)
    while True:
        try:
            report = collect()
            response = requests.post(endpoint, json=report, headers=headers, timeout=12)
            if response.ok:
                print(f"[{datetime.now().isoformat(timespec='seconds')}] Report sent. CPU={report['cpu_percent']}% RAM={report['memory_percent']}%", flush=True)
            else:
                print(f"Monitor API error {response.status_code}: {response.text[:300]}", flush=True)
        except Exception as exc:
            print(f"Agent error: {exc}", flush=True)
        time.sleep(max(10, INTERVAL_SECONDS))


if __name__ == "__main__":
    main()
