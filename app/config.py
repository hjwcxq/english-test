"""Runtime configuration read only from the trusted process environment."""

from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULT_ORIGINS = (
    "http://127.0.0.1:8000",
    "http://localhost:8000",
)
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8000


def _normalise_origin(value: str) -> str:
    return value.strip().rstrip("/")


def allowed_origins() -> list[str]:
    """Return the trusted browser origins.

    An invalid or empty environment value fails closed (no origin accepted)
    rather than trusting an arbitrary request header.
    """
    raw = os.environ.get("VOCAB_APP_ORIGINS")
    if not raw:
        return list(DEFAULT_ORIGINS)
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [
        _normalise_origin(item)
        for item in parsed
        if isinstance(item, str) and item.strip()
    ]


def secure_cookies() -> bool:
    value = os.environ.get("VOCAB_COOKIE_SECURE", "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def data_dir() -> Path:
    """Private runtime directory; never inside the source repository."""
    configured = os.environ.get("VOCAB_DATA_DIR")
    if configured:
        location = Path(configured).expanduser()
    else:
        location = Path.home() / ".local" / "share" / "english-test"
    location.mkdir(parents=True, exist_ok=True)
    return location


def database_path() -> Path:
    return data_dir() / "vocab.sqlite3"


def server_host() -> str:
    return os.environ.get("VOCAB_HOST", DEFAULT_HOST)


def server_port() -> int:
    raw = os.environ.get("VOCAB_PORT", str(DEFAULT_PORT))
    try:
        port = int(raw)
    except (TypeError, ValueError):
        port = DEFAULT_PORT
    return port if 0 <= port <= 65535 else DEFAULT_PORT
