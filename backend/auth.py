
import base64
import hashlib
import hmac
import json
import os
import secrets
import time


TOKEN_LIFETIME_SECONDS = 30 * 60
PASSWORD_ITERATIONS = 600_000


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def hash_password(password: str) -> str:
    if not password or len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")

    salt = secrets.token_bytes(16)
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )

    return (
        f"pbkdf2_sha256${PASSWORD_ITERATIONS}$"
        f"{_b64encode(salt)}${_b64encode(derived_key)}"
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt_text, key_text = stored_hash.split("$")

        if algorithm != "pbkdf2_sha256":
            return False

        rounds = int(iterations)
        if rounds < 1:
            return False

        salt = _b64decode(salt_text)
        expected_key = _b64decode(key_text)

        actual_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            rounds,
        )

        return hmac.compare_digest(actual_key, expected_key)
    except (ValueError, TypeError, UnicodeError):
        return False


def _get_token_secret() -> bytes:
    secret = os.getenv("SENTINELAI_TOKEN_SECRET", "")

    if len(secret) < 32:
        raise RuntimeError(
            "SENTINELAI_TOKEN_SECRET must be configured with "
            "a random secret of at least 32 characters."
        )

    return secret.encode("utf-8")


def create_access_token(username: str, role: str = "admin") -> str:
    now = int(time.time())

    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + TOKEN_LIFETIME_SECONDS,
        "nonce": secrets.token_hex(8),
    }

    encoded_payload = _b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )

    signature = hmac.new(
        _get_token_secret(),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()

    return f"{encoded_payload}.{_b64encode(signature)}"


def verify_access_token(token: str) -> dict:
    try:
        encoded_payload, encoded_signature = token.split(".")

        expected_signature = hmac.new(
            _get_token_secret(),
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()

        supplied_signature = _b64decode(encoded_signature)

        if not hmac.compare_digest(
            expected_signature,
            supplied_signature,
        ):
            raise ValueError("Invalid token signature.")

        payload = json.loads(_b64decode(encoded_payload))

        if not isinstance(payload, dict):
            raise ValueError("Invalid token payload.")

        if not isinstance(payload.get("sub"), str) or not payload["sub"]:
            raise ValueError("Invalid token subject.")

        if payload.get("role") != "admin":
            raise ValueError("Insufficient role.")

        if not isinstance(payload.get("exp"), int):
            raise ValueError("Invalid token expiry.")

        if payload["exp"] <= int(time.time()):
            raise ValueError("Token expired.")

        return payload

    except (
        ValueError,
        TypeError,
        KeyError,
        UnicodeError,
        json.JSONDecodeError,
    ):
        raise ValueError("Invalid or expired access token.")
