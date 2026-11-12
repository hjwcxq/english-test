"""Trusted CLI initialization and capability-boundary integration tests."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app import cli, db
from app.testkit import RunningServer, fixture, qa_username


class TrustedInitializationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.database = Path(self.tmp.name) / "vocab.sqlite3"
        db.migrate(self.database)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _environment(self) -> dict[str, str]:
        return {
            "VOCAB_DATA_DIR": self.tmp.name,
            "VOCAB_TEACHER_USERNAME": qa_username(),
            "VOCAB_TEACHER_PASSWORD": fixture(),
            "VOCAB_TEACHER_CLASS_IDS": json.dumps(["A"]),
        }

    def test_local_cli_creates_the_only_usable_teacher_account(self):
        stdout = io.StringIO()
        with mock.patch.dict(os.environ, self._environment(), clear=False):
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(cli.main(["create-teacher"]), 0)
        emitted = json.loads(stdout.getvalue())
        self.assertTrue(emitted["ok"])
        self.assertEqual(emitted["class_ids"], ["A"])
        self.assertNotIn(fixture(), stdout.getvalue())

        server = RunningServer(self.database)
        try:
            response, cookie = server.login_teacher()
            self.assertEqual(response.status, 200)
            self.assertIsNotNone(cookie)
            self.assertEqual(server.me(cookie).json()["class_ids"], ["A"])
        finally:
            server.close()

    def test_cli_requires_all_trusted_environment_inputs(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            for name in (
                "VOCAB_TEACHER_USERNAME",
                "VOCAB_TEACHER_PASSWORD",
                "VOCAB_TEACHER_CLASS_IDS",
            ):
                os.environ.pop(name, None)
            with mock.patch.dict(
                os.environ, {"VOCAB_DATA_DIR": self.tmp.name}, clear=False
            ):
                with self.assertRaises(SystemExit):
                    cli.main(["create-teacher"])

    def test_cli_rejects_non_json_class_ids(self):
        environment = self._environment()
        environment["VOCAB_TEACHER_CLASS_IDS"] = "A,B"
        with mock.patch.dict(os.environ, environment, clear=False):
            with self.assertRaises(SystemExit):
                cli.main(["create-teacher"])

    def test_no_http_endpoint_can_create_teacher_accounts(self):
        server = RunningServer(self.database)
        try:
            for path in (
                "/api/auth/teacher/register",
                "/api/auth/teacher/init",
                "/api/teacher/init",
            ):
                with self.subTest(path=path):
                    response = server.request(
                        "POST",
                        path,
                        payload={
                            "username": "attacker",
                            "password": fixture(),
                            "teacher": True,
                        },
                        origin="http://127.0.0.1:8000",
                    )
                    self.assertIn(response.status, (401, 404))
                    self.assertNotEqual(response.status, 200)
            connection = db.connect(self.database)
            try:
                count = connection.execute(
                    "SELECT COUNT(*) AS total FROM teachers"
                ).fetchone()["total"]
            finally:
                connection.close()
            self.assertEqual(count, 0)
        finally:
            server.close()

    def test_cli_refuses_to_run_without_environment_even_if_database_is_ready(self):
        server = RunningServer(self.database)
        try:
            self.assertEqual(server.request("GET", "/health").status, 200)
        finally:
            server.close()
        with mock.patch.dict(os.environ, {"VOCAB_DATA_DIR": self.tmp.name}, clear=False):
            os.environ.pop("VOCAB_TEACHER_USERNAME", None)
            os.environ.pop("VOCAB_TEACHER_PASSWORD", None)
            os.environ.pop("VOCAB_TEACHER_CLASS_IDS", None)
            with self.assertRaises(SystemExit):
                cli.main(["create-teacher"])


if __name__ == "__main__":
    unittest.main()
