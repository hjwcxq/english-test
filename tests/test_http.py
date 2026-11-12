"""HTTP skeleton, public health/capability and page contract tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app import db
from app.testkit import TRUSTED_ORIGIN, RunningServer, prepare_teacher, fixture, qa_username


class HttpContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.database = Path(self.tmp.name) / "vocab.sqlite3"
        db.migrate(self.database)
        prepare_teacher(self.database)
        self.server = RunningServer(self.database)

    def tearDown(self) -> None:
        self.server.close()
        self.tmp.cleanup()

    def test_health_reports_exact_foundation_contract(self):
        response = self.server.request("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(
            response.json(),
            {"status": "ok", "project_id": "english-test", "schema_version": 1},
        )
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_capabilities_are_reported_as_not_configured(self):
        response = self.server.request("GET", "/api/capabilities")
        self.assertEqual(response.status, 200)
        body = response.text
        for name in ("face", "voice", "audio"):
            self.assertIn(name, body)
        payload = response.json()
        self.assertEqual(payload["project_id"], "english-test")
        self.assertFalse(payload["capabilities"]["face"]["configured"])
        self.assertFalse(payload["capabilities"]["voice"]["configured"])
        self.assertFalse(payload["capabilities"]["audio"]["configured"])

    def test_pad_page_is_student_only_skeleton(self):
        response = self.server.request("GET", "/pad")
        self.assertEqual(response.status, 200)
        self.assertIn("今日黄金任务", response.text)
        self.assertIn("演示", response.text)
        self.assertIn("/fəˈnɒmɪnən/", response.text)
        self.assertIn("全屏", response.text)
        self.assertIn("待建设", response.text)
        self.assertNotIn("教师登录", response.text)
        self.assertNotIn("密钥", response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_teacher_page_requires_login_form(self):
        response = self.server.request("GET", "/teacher")
        self.assertEqual(response.status, 200)
        self.assertIn("教师登录", response.text)
        self.assertIn("待建设", response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_private_api_refuses_anonymous_teacher_data(self):
        response = self.server.request("GET", "/api/teacher/students")
        self.assertEqual(response.status, 401)
        self.assertEqual(response.json(), {"error": "authentication_required"})
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_unknown_route_is_404(self):
        response = self.server.request("GET", "/api/auth/teacher/register")
        self.assertEqual(response.status, 404)
        self.assertEqual(response.json(), {"error": "not_found"})

    def test_no_public_teacher_initializer_accepts_teacher_flag(self):
        response = self.server.request(
            "POST",
            "/api/auth/teacher/login",
            payload={
                "username": "admin",
                "password": "admin",
                "teacher": True,
            },
            origin=TRUSTED_ORIGIN,
        )
        self.assertEqual(response.status, 401)
        self.assertEqual(response.json(), {"error": "invalid_credentials"})
        self.assertIsNone(response.cookie())

    def test_session_cookie_is_secure_when_configured_for_https(self):
        secure_server = RunningServer(self.database, secure_cookie=True)
        try:
            response, cookie = secure_server.login_teacher()
            self.assertEqual(response.status, 200)
            self.assertIsNotNone(cookie)
            self.assertIn("secure", response.headers["set-cookie"].lower())
        finally:
            secure_server.close()

    def test_trusted_credentials_still_work(self):
        response, cookie = self.server.login_teacher(qa_username(), fixture())
        self.assertEqual(response.status, 200)
        self.assertIsNotNone(cookie)


if __name__ == "__main__":
    unittest.main()
