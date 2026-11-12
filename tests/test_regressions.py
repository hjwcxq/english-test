"""Migration, restart and persistence regression checks."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app import auth, db
from app.testkit import RunningServer, prepare_teacher, fixture, qa_username


class MigrationAndRestartTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.database = Path(self.tmp.name) / "vocab.sqlite3"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_initial_migration_is_transactional_reentrant_and_preserves_rows(self):
        self.assertTrue(db.migrate(self.database))
        prepare_teacher(self.database, class_ids=["A"])
        db.upsert_student(
            self.database,
            student_id="real-a-1",
            display_name="甲同学",
            class_id="A",
            realm="real",
        )
        self.assertFalse(db.migrate(self.database))
        self.assertFalse(db.migrate(self.database))
        self.assertEqual(db.schema_version(self.database), 1)

        connection = db.connect(self.database)
        try:
            teacher = connection.execute(
                "SELECT * FROM teachers WHERE username = ?",
                (qa_username(),),
            ).fetchone()
            students = connection.execute(
                "SELECT student_id FROM students ORDER BY student_id"
            ).fetchall()
        finally:
            connection.close()
        self.assertIsNotNone(teacher)
        self.assertEqual(len(teacher["password_hash"]), 64)
        self.assertEqual(int(teacher["password_iterations"]), 240000)
        identifiers = {row["student_id"] for row in students}
        self.assertIn("real-a-1", identifiers)
        self.assertEqual(
            {"demo-zhang", "demo-li", "demo-wang", "demo-chen"} - identifiers,
            set(),
        )

    def test_restart_preserves_account_session_and_records(self):
        db.migrate(self.database)
        prepare_teacher(self.database, class_ids=["A"])
        db.upsert_student(
            self.database,
            student_id="real-a-1",
            display_name="甲同学",
            class_id="A",
            realm="real",
        )
        first = RunningServer(self.database)
        try:
            login, cookie = first.login_teacher()
            self.assertEqual(login.status, 200)
            first_me = first.me(cookie).json()
            self.assertEqual(first_me["display_name"], qa_username())
        finally:
            first.close()

        second = RunningServer(self.database)
        try:
            self.assertEqual(second.me(cookie).status, 200)
            students = second.request(
                "GET", "/api/teacher/students", cookie=cookie
            ).json()
            self.assertEqual(
                [item["student_id"] for item in students["students"]],
                ["real-a-1"],
            )
            relogin, relogin_cookie = second.login_teacher()
            self.assertEqual(relogin.status, 200)
            self.assertEqual(second.me(relogin_cookie).status, 200)
        finally:
            second.close()

    def test_database_and_session_files_do_not_store_the_plain_credential(self):
        db.migrate(self.database)
        prepare_teacher(self.database)
        server = RunningServer(self.database)
        try:
            _, cookie = server.login_teacher()
            self.assertIsNotNone(cookie)
        finally:
            server.close()
        raw = b"".join(
            path.read_bytes() for path in Path(self.tmp.name).glob("*") if path.is_file()
        )
        self.assertNotIn(fixture().encode("utf-8"), raw)
        self.assertNotIn(cookie.encode("utf-8"), raw)
        self.assertIn(auth.token_digest(cookie).encode("utf-8"), raw)

    def test_server_starts_with_schema_version_one(self):
        db.migrate(self.database)
        server = RunningServer(self.database)
        try:
            payload = server.request("GET", "/health").json()
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(db.schema_version(self.database), 1)
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
