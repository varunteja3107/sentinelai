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
DEVICE_TOKEN_FILE = BASE_DIR / "device_credential_token"

API_URL = "https://sentinelai-api-2pqw.onrender.com"
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

    legacy_token = TOKEN_FILE.read_text().strip() if TOKEN_FILE.exists() else ""
    device_token = (
        DEVICE_TOKEN_FILE.read_text().strip()
        if DEVICE_TOKEN_FILE.exists()
        else ""
    )

    if not device_token and not legacy_token:
        legacy_token = getpass.getpass(
            "Paste the existing DEVICE_MONITOR_TOKEN configured on the backend: "
        ).strip()

    if device_token and len(device_token) < 32:
        raise SystemExit("Individual device credential is invalid or too short.")

    if legacy_token and len(legacy_token) < 32:
        raise SystemExit("Legacy shared token is invalid or too short.")

    if legacy_token:
        TOKEN_FILE.write_text(legacy_token + chr(10))
        TOKEN_FILE.chmod(0o600)

    if device_token:
        DEVICE_TOKEN_FILE.write_text(device_token + chr(10))
        DEVICE_TOKEN_FILE.chmod(0o600)

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
            "DEVICE_MONITOR_TOKEN": legacy_token,
            "SENTINELAI_DEVICE_TOKEN": device_token,
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
    print("Authentication credentials were not printed.")
    print("Individual device credential is preferred when installed.")
    print("Location tracking remains separately opt-in in your browser.")


if __name__ == "__main__":
    main()
