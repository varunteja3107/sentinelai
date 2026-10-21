#!/usr/bin/env python3
"""Install SentinelAI's Mac monitoring agent outside protected Desktop folders."""
from pathlib import Path
import getpass
import os
import plistlib
import shutil
import subprocess
import sys

SOURCE_DIR = Path(__file__).resolve().parent
HOME = Path.home()
BASE_DIR = HOME / ".sentinelai"
INSTALL_DIR = BASE_DIR / "agent"
VENV_DIR = INSTALL_DIR / ".venv"
PYTHON = VENV_DIR / "bin" / "python"
TOKEN_FILE = BASE_DIR / "device_monitor_token"

API_URL = "https://sentinelai-wnno.onrender.com"
LABEL = "com.sentinelai.device-monitor"
PLIST = HOME / "Library" / "LaunchAgents" / f"{LABEL}.plist"
LOG_DIR = HOME / "Library" / "Logs"
LOG_FILE = LOG_DIR / "sentinelai-device-monitor.log"


def run(args):
    subprocess.run([str(x) for x in args], check=True)


def main():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    PLIST.parent.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    token = TOKEN_FILE.read_text().strip() if TOKEN_FILE.exists() else ""
    if not token:
        token = getpass.getpass(
            "Paste the DEVICE_MONITOR_TOKEN configured in Render: "
        ).strip()

    if len(token) < 32:
        raise SystemExit("Token is missing or too short.")

    TOKEN_FILE.write_text(token + "\n")
    TOKEN_FILE.chmod(0o600)

    for name in ("agent.py", "requirements.txt"):
        source = SOURCE_DIR / name
        if not source.is_file():
            raise SystemExit(f"Required source file missing: {source}")
        shutil.copy2(source, INSTALL_DIR / name)

    if not PYTHON.exists():
        run([sys.executable, "-m", "venv", str(VENV_DIR)])

    run([PYTHON, "-m", "pip", "install", "-r",
         INSTALL_DIR / "requirements.txt"])

    config = {
        "Label": LABEL,
        "ProgramArguments": [str(PYTHON), str(INSTALL_DIR / "agent.py")],
        "WorkingDirectory": str(INSTALL_DIR),
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "StandardOutPath": str(LOG_FILE),
        "StandardErrorPath": str(LOG_FILE),
        "EnvironmentVariables": {
            "DEVICE_MONITOR_TOKEN": token,
            "SENTINELAI_API_URL": API_URL,
            "SENTINELAI_MONITOR_INTERVAL": "15",
            "PYTHONUNBUFFERED": "1",
        },
    }

    with PLIST.open("wb") as f:
        plistlib.dump(config, f)
    PLIST.chmod(0o600)

    domain = f"gui/{os.getuid()}"
    subprocess.run(
        ["launchctl", "bootout", domain, str(PLIST)],
        check=False, capture_output=True,
    )
    run(["launchctl", "bootstrap", domain, PLIST])
    run(["launchctl", "kickstart", "-k", f"{domain}/{LABEL}"])

    print("\nSentinelAI monitoring agent reinstalled.")
    print(f"Agent location: {INSTALL_DIR}")
    print(f"Log file: {LOG_FILE}")
    print("Token was not printed. Ensure Render has the same token.")
    print("Location tracking remains separately opt-in in your browser.")


if __name__ == "__main__":
    main()
