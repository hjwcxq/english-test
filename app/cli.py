"""Local trusted operations CLI.

Only this process entry point can create a real teacher account. It reads the
three documented environment variables and never exposes an HTTP initializer.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import auth, config, db


def _env_value(name: str) -> str:
    return os.environ.get(name) or ""


def _teacher_inputs() -> tuple[str, str, list[str]]:
    username = _env_value("VOCAB_TEACHER_USERNAME").strip()
    password = _env_value("VOCAB_TEACHER_PASSWORD")
    raw_classes = _env_value("VOCAB_TEACHER_CLASS_IDS")
    if not username:
        raise SystemExit("VOCAB_TEACHER_USERNAME is required")
    if not password:
        raise SystemExit("VOCAB_TEACHER_PASSWORD is required")
    try:
        parsed = json.loads(raw_classes)
    except (TypeError, ValueError) as exc:
        raise SystemExit("VOCAB_TEACHER_CLASS_IDS must be a JSON string array") from exc
    if not isinstance(parsed, list) or not parsed:
        raise SystemExit("VOCAB_TEACHER_CLASS_IDS must be a non-empty JSON string array")
    class_ids = [item.strip() for item in parsed if isinstance(item, str) and item.strip()]
    if not class_ids or len(class_ids) != len(parsed):
        raise SystemExit("VOCAB_TEACHER_CLASS_IDS must contain only strings")
    return username, password, class_ids


def create_teacher_command() -> int:
    # Validate every trusted input before touching the private data directory.
    username, password, class_ids = _teacher_inputs()
    database = config.database_path()
    db.migrate(database)
    material = auth.hash_password(password)
    db.create_teacher(
        database,
        username=username,
        display_name=username,
        password_material=material,
        class_ids=class_ids,
    )
    print(
        json.dumps(
            {
                "ok": True,
                "username": username,
                "class_ids": class_ids,
                "database": str(database),
            },
            ensure_ascii=False,
        )
    )
    return 0


def init_db_command() -> int:
    database = config.database_path()
    changed = db.migrate(database)
    print(
        json.dumps(
            {
                "ok": True,
                "database": str(database),
                "schema_version": db.schema_version(database),
                "migrated": changed,
            },
            ensure_ascii=False,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("create-teacher", help="create or refresh a trusted teacher account")
    sub.add_parser("init-db", help="apply transactional, re-entrant migrations")
    args = parser.parse_args(argv)
    if args.command == "create-teacher":
        return create_teacher_command()
    return init_db_command()


if __name__ == "__main__":
    sys.exit(main())
