from pathlib import Path
from getpass import getpass
import shutil
from auth import hash_password, verify_password

p = Path(".env")
lines = p.read_text().splitlines() if p.exists() else []

username = input("New admin username: ").strip()
password = getpass("New password (minimum 12 characters): ")
confirm = getpass("Confirm password: ")

if not username:
    raise SystemExit("Username cannot be empty.")
if len(password) < 12:
    raise SystemExit("Password must contain at least 12 characters.")
if password != confirm:
    raise SystemExit("Passwords do not match.")

backup = Path(".env.before_final_reset")
if p.exists() and not backup.exists():
    shutil.copy2(p, backup)

updates = {
    "SENTINELAI_ADMIN_USERNAME": username,
    "SENTINELAI_ADMIN_PASSWORD_HASH": hash_password(password),
}

for key, value in updates.items():
    lines = [line for line in lines if not line.startswith(key + "=")]
    lines.append(f"{key}={value}")

p.write_text("\n".join(lines) + "\n")

saved = dict(
    line.split("=", 1)
    for line in p.read_text().splitlines()
    if "=" in line
)

print("Username saved:", saved.get("SENTINELAI_ADMIN_USERNAME") == username)
print("Password hash verified:", verify_password(
    password, saved["SENTINELAI_ADMIN_PASSWORD_HASH"]
))
print("ADMIN RESET SUCCESSFUL")
