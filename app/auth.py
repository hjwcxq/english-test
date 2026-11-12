"""Password, server-session and CSRF primitives for the W4 foundation."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Any

from . import db

PBKDF2_ITERATIONS = 240000
PBKDF2_ALGORITHM = "sha256"
SESSION_COOKIE = "vocab_session"
SESSION_TTL_SECONDS = 8 * 60 * 60


def hash_password(
    value: str,
    *,
    salt: bytes | None = None,
    iterations: int = PBKDF2_ITERATIONS,
) -> dict[str, Any]:
    """Derive the salted PBKDF2 material stored for a teacher account."""
    if not isinstance(value, str) or value == "":
        raise ValueError("empty credential")
    salt_bytes = salt if salt is not None else secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM, value.encode("utf-8"), salt_bytes, iterations
    )
    return {
        "password_hash": derived.hex(),
        "password_salt": salt_bytes.hex(),
        "password_iterations": iterations,
    }


def verify_password(
    value: str,
    password_hash: str,
    password_salt: str,
    password_iterations: int,
) -> bool:
    try:
        salt_bytes = bytes.fromhex(password_salt)
        iterations = int(password_iterations)
        expected = bytes.fromhex(password_hash)
    except (TypeError, ValueError):
        return False
    if not isinstance(value, str) or value == "" or iterations <= 0:
        return False
    derived = hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM, value.encode("utf-8"), salt_bytes, iterations
    )
    return hmac.compare_digest(derived, expected)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_session(
    database: str | Path,
    *,
    role: str,
    realm: str,
    principal_id: str,
    display_name: str,
    class_ids: list[str],
    now: int | None = None,
) -> dict[str, Any]:
    issued_at = int(time.time() if now is None else now)
    expires_at = issued_at + SESSION_TTL_SECONDS
    session_value = secrets.token_urlsafe(32)
    csrf_value = secrets.token_urlsafe(32)
    connection = db.connect(database)
    try:
        connection.execute(
            "INSERT INTO sessions"
            "(token_digest, role, realm, principal_id, display_name, class_ids, "
            " csrf_token, created_at, expires_at) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                token_digest(session_value),
                role,
                realm,
                principal_id,
                display_name,
                json.dumps(class_ids, ensure_ascii=False),
                csrf_value,
                issued_at,
                expires_at,
            ),
        )
    finally:
        connection.close()
    return {
        "token": session_value,
        "csrf_token": csrf_value,
        "expires_at": expires_at,
        "role": role,
        "realm": realm,
        "principal_id": principal_id,
        "display_name": display_name,
        "class_ids": list(class_ids),
    }


def resolve_session(
    database: str | Path, token: str | None, *, now: int | None = None
) -> dict[str, Any] | None:
    if not isinstance(token, str) or not token:
        return None
    current = int(time.time() if now is None else now)
    connection = db.connect(database)
    try:
        row = connection.execute(
            "SELECT * FROM sessions WHERE token_digest = ?",
            (token_digest(token),),
        ).fetchone()
    finally:
        connection.close()
    if row is None or row["revoked_at"] is not None:
        return None
    if int(row["expires_at"]) <= current:
        return None
    try:
        class_ids = json.loads(row["class_ids"])
    except (TypeError, ValueError):
        class_ids = []
    return {
        "session_id": int(row["id"]),
        "role": row["role"],
        "realm": row["realm"],
        "principal_id": row["principal_id"],
        "display_name": row["display_name"],
        "class_ids": class_ids if isinstance(class_ids, list) else [],
        "csrf_token": row["csrf_token"],
        "created_at": int(row["created_at"]),
        "expires_at": int(row["expires_at"]),
    }


def revoke_session(database: str | Path, session_id: int) -> None:
    connection = db.connect(database)
    try:
        connection.execute(
            "UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (int(time.time()), int(session_id)),
        )
    finally:
        connection.close()


def authenticate_teacher(
    database: str | Path, username: str, supplied: str
) -> dict[str, Any] | None:
    row = db.find_teacher(database, username)
    if row is None:
        # Burn the same derivation shape for an unknown account so timing does
        # not cheaply distinguish missing accounts from wrong credentials.
        verify_password(
            supplied,
            "00" * 32,
            "00" * 16,
            PBKDF2_ITERATIONS,
        )
        return None
    if not verify_password(
        supplied,
        password_hash=row["password_hash"],
        password_salt=row["password_salt"],
        password_iterations=row["password_iterations"],
    ):
        return None
    try:
        class_ids = json.loads(row["class_ids"])
    except (TypeError, ValueError):
        class_ids = []
    return {
        "username": row["username"],
        "display_name": row["display_name"],
        "class_ids": class_ids if isinstance(class_ids, list) else [],
    }
