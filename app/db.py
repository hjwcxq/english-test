"""SQLite storage, transactional migrations and trusted seeding."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = ROOT / "migrations"

DEMO_STUDENTS: tuple[dict[str, str], ...] = (
    {"student_id": "demo-zhang", "display_name": "张晓明", "class_id": "demo"},
    {"student_id": "demo-li", "display_name": "李佳琪", "class_id": "demo"},
    {"student_id": "demo-wang", "display_name": "王浩然", "class_id": "demo"},
    {"student_id": "demo-chen", "display_name": "陈思远", "class_id": "demo"},
)
DEMO_BY_ID = {row["student_id"]: row for row in DEMO_STUDENTS}


def connect(database: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(database), timeout=10, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def _migration_statements(version: int) -> list[str]:
    path = MIGRATIONS_DIR / f"{version:03d}_initial.sql"
    if not path.is_file():
        raise RuntimeError(f"missing migration file: {path.name}")
    # Strip whole-line comments before splitting so a semicolon in prose can
    # never turn the rest of a comment into executable SQL.
    sql_lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("--")
    ]
    statements = [part.strip() for part in "\n".join(sql_lines).split(";")]
    return [statement for statement in statements if statement]


def migrate(database: str | Path) -> bool:
    """Apply pending migrations atomically.

    Returns True when a migration ran and False when the database was already
    at the current version. Existing rows are preserved.
    """
    location = Path(database)
    if location.parent != Path("."):
        location.parent.mkdir(parents=True, exist_ok=True)
    connection = connect(database)
    try:
        current = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if current >= SCHEMA_VERSION:
            return False
        connection.execute("BEGIN IMMEDIATE")
        try:
            for statement in _migration_statements(SCHEMA_VERSION):
                connection.execute(statement)
            now = int(time.time())
            connection.execute(
                "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(SCHEMA_VERSION),),
            )
            connection.execute(
                "INSERT INTO schema_meta(key, value) VALUES('migrated_at', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(now),),
            )
            for student in DEMO_STUDENTS:
                connection.execute(
                    "INSERT OR IGNORE INTO students"
                    "(student_id, display_name, class_id, realm, created_at) "
                    "VALUES(?, ?, ?, 'demo', ?)",
                    (
                        student["student_id"],
                        student["display_name"],
                        student["class_id"],
                        now,
                    ),
                )
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
        return True
    finally:
        connection.close()


def schema_version(database: str | Path) -> int:
    connection = connect(database)
    try:
        return int(connection.execute("PRAGMA user_version").fetchone()[0])
    finally:
        connection.close()


def create_teacher(
    database: str | Path,
    *,
    username: str,
    display_name: str,
    password_material: dict[str, Any],
    class_ids: list[str],
) -> None:
    """Create or refresh one trusted teacher account.

    This function is only reachable from the local trusted CLI and test
    fixtures; there is deliberately no HTTP endpoint for account creation.
    """
    now = int(time.time())
    connection = connect(database)
    try:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT id FROM teachers WHERE username = ?", (username,)
        ).fetchone()
        if existing is None:
            connection.execute(
                "INSERT INTO teachers"
                "(username, display_name, password_hash, password_salt, "
                " password_iterations, class_ids, created_at, updated_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    username,
                    display_name,
                    password_material["password_hash"],
                    password_material["password_salt"],
                    int(password_material["password_iterations"]),
                    json.dumps(class_ids, ensure_ascii=False),
                    now,
                    now,
                ),
            )
        else:
            connection.execute(
                "UPDATE teachers SET display_name = ?, password_hash = ?, "
                "password_salt = ?, password_iterations = ?, class_ids = ?, "
                "updated_at = ? WHERE username = ?",
                (
                    display_name,
                    password_material["password_hash"],
                    password_material["password_salt"],
                    int(password_material["password_iterations"]),
                    json.dumps(class_ids, ensure_ascii=False),
                    now,
                    username,
                ),
            )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def find_teacher(database: str | Path, username: str) -> sqlite3.Row | None:
    connection = connect(database)
    try:
        return connection.execute(
            "SELECT * FROM teachers WHERE username = ?", (username,)
        ).fetchone()
    finally:
        connection.close()


def upsert_student(
    database: str | Path,
    *,
    student_id: str,
    display_name: str,
    class_id: str,
    realm: str = "real",
) -> None:
    """Trusted fixture/operations helper; not exposed over HTTP."""
    connection = connect(database)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "INSERT INTO students(student_id, display_name, class_id, realm, created_at) "
            "VALUES(?, ?, ?, ?, ?) "
            "ON CONFLICT(student_id) DO UPDATE SET "
            "display_name = excluded.display_name, class_id = excluded.class_id, "
            "realm = excluded.realm",
            (student_id, display_name, class_id, realm, int(time.time())),
        )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def list_students_for_teacher(
    database: str | Path, *, realm: str, class_ids: list[str]
) -> list[dict[str, str]]:
    if not class_ids:
        return []
    placeholders = ",".join("?" for _ in class_ids)
    connection = connect(database)
    try:
        rows = connection.execute(
            "SELECT student_id, display_name, class_id FROM students "
            f"WHERE realm = ? AND class_id IN ({placeholders}) "
            "ORDER BY class_id, student_id",
            [realm, *class_ids],
        ).fetchall()
        return [
            {
                "student_id": row["student_id"],
                "display_name": row["display_name"],
                "class_id": row["class_id"],
            }
            for row in rows
        ]
    finally:
        connection.close()
