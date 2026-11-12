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

    def test_student_private_paths_authenticate_before_unimplemented_404(self):
        for path in (
            "/api/student",
            "/api/student/",
            "/api/student/tasks",
            "/api/student/submit",
            "/api/student/report",
            "/api/student/tasks/future/deep/path",
        ):
            with self.subTest(path=path):
                response = self.server.request("GET", path)
                self.assertEqual(response.status, 401)
                self.assertEqual(response.json(), {"error": "authentication_required"})
                self.assertEqual(response.headers["cache-control"], "no-store")

        invalid = self.server.request(
            "GET", "/api/student/tasks", cookie="not-a-real-student-session"
        )
        self.assertEqual(invalid.status, 401)
        self.assertEqual(invalid.json(), {"error": "authentication_required"})

    def test_student_path_matching_does_not_capture_lookalike_routes(self):
        for path in ("/api/students", "/api/student-admin", "/api/studentx/report"):
            with self.subTest(path=path):
                response = self.server.request("GET", path)
                self.assertEqual(response.status, 404)
                self.assertEqual(response.json(), {"error": "not_found"})

    def test_student_get_enforces_role_and_keeps_unimplemented_endpoints_404(self):
        _, teacher_cookie = self.server.login_teacher()
        refused = self.server.request(
            "GET", "/api/student/tasks", cookie=teacher_cookie
        )
        self.assertEqual(refused.status, 403)
        self.assertEqual(refused.json(), {"error": "forbidden"})

        _, student_cookie = self.server.login_demo("demo-zhang")
        for path in ("/api/student", "/api/student/tasks", "/api/student/report"):
            with self.subTest(path=path):
                response = self.server.request("GET", path, cookie=student_cookie)
                self.assertEqual(response.status, 404)
                self.assertEqual(response.json(), {"error": "not_found"})
                self.assertEqual(response.headers["cache-control"], "no-store")

    def test_student_post_authenticates_then_enforces_origin_and_csrf(self):
        for path in (
            "/api/student",
            "/api/student/",
            "/api/student/tasks",
            "/api/student/submit",
            "/api/student/report",
            "/api/student/future/deep/path",
        ):
            with self.subTest(path=path):
                anonymous = self.server.request(
                    "POST", path, payload={"answer": "x"}
                )
                self.assertEqual(anonymous.status, 401)
                self.assertEqual(
                    anonymous.json(), {"error": "authentication_required"}
                )

        _, student_cookie = self.server.login_demo("demo-zhang")
        student_me = self.server.me(student_cookie).json()
        missing_origin = self.server.request(
            "POST",
            "/api/student/tasks/submit",
            payload={"answer": "x"},
            cookie=student_cookie,
            csrf=student_me["csrf_token"],
        )
        self.assertEqual(missing_origin.status, 403)
        self.assertEqual(missing_origin.json(), {"error": "forbidden"})

        missing_csrf = self.server.request(
            "POST",
            "/api/student/tasks/submit",
            payload={"answer": "x"},
            cookie=student_cookie,
            origin=TRUSTED_ORIGIN,
        )
        self.assertEqual(missing_csrf.status, 403)
        self.assertEqual(missing_csrf.json(), {"error": "forbidden"})

        for path in (
            "/api/student",
            "/api/student/",
            "/api/student/tasks",
            "/api/student/submit",
            "/api/student/report",
            "/api/student/future/deep/path",
        ):
            with self.subTest(path=path):
                accepted_but_unimplemented = self.server.request(
                    "POST",
                    path,
                    payload={"answer": "x"},
                    cookie=student_cookie,
                    csrf=student_me["csrf_token"],
                    origin=TRUSTED_ORIGIN,
                )
                self.assertEqual(accepted_but_unimplemented.status, 404)
                self.assertEqual(
                    accepted_but_unimplemented.json(), {"error": "not_found"}
                )

        _, teacher_cookie = self.server.login_teacher()
        teacher_me = self.server.me(teacher_cookie).json()
        teacher_refused = self.server.request(
            "POST",
            "/api/student/tasks/submit",
            payload={"answer": "x"},
            cookie=teacher_cookie,
            csrf=teacher_me["csrf_token"],
            origin=TRUSTED_ORIGIN,
        )
        self.assertEqual(teacher_refused.status, 403)
        self.assertEqual(teacher_refused.json(), {"error": "forbidden"})

    def test_pad_fullscreen_and_logout_are_real_reachable_controls(self):
        response = self.server.request("GET", "/pad")
        self.assertEqual(response.status, 200)
        text = response.text
        self.assertIn('id="fullscreen"', text)
        self.assertIn('id="exit"', text)
        self.assertIn("document.documentElement", text)
        self.assertIn("document.fullscreenElement", text)
        self.assertIn("requestFullscreen", text)
        self.assertIn("exitFullscreen", text)
        self.assertIn("fullscreenchange", text)
        self.assertIn("fullscreenerror", text)
        self.assertIn("/api/auth/logout", text)
        self.assertIn("退出未确认，请重试", text)
        self.assertIn("已退出当前学生会话", text)
        self.assertNotIn("pad-shell').requestFullscreen", text)


if __name__ == "__main__":
    unittest.main()
