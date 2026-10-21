#!/usr/bin/env python3
"""Install or update the SentinelAI monitoring agent as a macOS LaunchAgent."""
from pathlib import Path
import getpass
import os
import plistlib
import subprocess
import sys

HERE = Path(__file__).resolve().parent
PYTHON = HERE / ".venv" / "bin" / "python"
TOKEN_FILE = Path.home() / ".sentinelai" / "device_monitor_token"
API_URL = "https://sentinelai-wnno.onrender.com"
LABEL = "com.sentinelai.device-monitor"
PLIST = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"
LOG_DIR = Path.home() / "Library" / "Logs"
LOG_FILE = LOG_DIR / "sentinelai-device-monitor.log"


def run(args):
    subprocess.run([str(x) for x in args], check=True)


def main():
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    token = ""
    if TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text().strip()
    if not token:
        token = getpass.getpass("Paste the DEVICE_MONITOR_TOKEN configured in Render: ").strip()
    if len(token) < 32:
        raise SystemExit("Token looks too short. Use a random token of at least 32 characters.")
    TOKEN_FILE.write_text(token + "\n")
    TOKEN_FILE.chmod(0o600)

    venv_dir = HERE / ".venv"
    if not PYTHON.exists():
        run([sys.executable, "-m", "venv", str(venv_dir)])
    run([PYTHON, "-m", "pip", "install", "--upgrade", "pip"])
    run([PYTHON, "-m", "pip", "install", "-r", HERE / "requirements.txt"])

    PLIST.parent.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    config = {
        "Label": LABEL,
        "ProgramArguments": [str(PYTHON), str(HERE / "agent.py")],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "StandardOutPath": str(LOG_FILE),
        "StandardErrorPath": str(LOG_FILE),
        "EnvironmentVariables": {
            "DEVICE_MONITOR_TOKEN": token,
            "SENTINELAI_API_URL": API_URL,
            "SENTINELAI_MONITOR_INTERVAL": "15",
        },
    }
    with PLIST.open("wb") as f:
        plistlib.dump(config, f)
    PLIST.chmod(0o600)

    domain = f"gui/{os.getuid()}"
    subprocess.run(["launchctl", "bootout", domain, str(PLIST)], check=False, capture_output=True)
    run(["launchctl", "bootstrap", domain, PLIST])
    run(["launchctl", "kickstart", "-k", f"{domain}/{LABEL}"])
    print("\nSentinelAI monitoring agent installed and started.")
    print(f"Logs: {LOG_FILE}")
    print("The agent starts at login and restarts if it exits. It cannot report while the Mac is shut down or asleep.")
    print("To stop it: launchctl bootout " + domain + " " + str(PLIST))


if __name__ == "__main__":
    main()
