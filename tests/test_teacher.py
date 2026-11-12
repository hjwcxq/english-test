"""Role, realm and authorised-class isolation for the teacher surface."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app import db
from app.testkit import RunningServer, prepare_teacher


class TeacherAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.database = Path(self.tmp.name) / "vocab.sqlite3"
        db.migrate(self.database)
        prepare_teacher(self.database, class_ids=["A"])
        db.upsert_student(
            self.database,
            student_id="real-a-1",
            display_name="甲同学",
            class_id="A",
            realm="real",
        )
        db.upsert_student(
            self.database,
            student_id="real-b-1",
            display_name="乙同学",
            class_id="B",
            realm="real",
        )
        self.server = RunningServer(self.database)

    def tearDown(self) -> None:
        self.server.close()
        self.tmp.cleanup()

    def test_demo_students_are_public_and_exactly_the_frozen_four(self):
        response = self.server.request("GET", "/api/demo/students")
        self.assertEqual(response.status, 200)
        payload = response.json()
        self.assertEqual(payload["realm"], "demo")
        identities = [item["student_id"] for item in payload["students"]]
        self.assertEqual(
            identities, ["demo-zhang", "demo-li", "demo-wang", "demo-chen"]
        )
        display = {item["student_id"]: item["display_name"] for item in payload["students"]}
        self.assertEqual(display["demo-zhang"], "张晓明")
        self.assertEqual(display["demo-li"], "李佳琪")
        self.assertEqual(display["demo-wang"], "王浩然")
        self.assertEqual(display["demo-chen"], "陈思远")

    def test_each_demo_identity_gets_an_isolated_demo_session(self):
        expected = {
            "demo-zhang": "张晓明",
            "demo-li": "李佳琪",
            "demo-wang": "王浩然",
            "demo-chen": "陈思远",
        }
        for student_id, display_name in expected.items():
            with self.subTest(student_id=student_id):
                response, cookie = self.server.login_demo(student_id)
                self.assertEqual(response.status, 200)
                self.assertEqual(response.json(), {"ok": True})
                payload = self.server.me(cookie).json()
                self.assertEqual(payload["role"], "student")
                self.assertEqual(payload["realm"], "demo")
                self.assertEqual(payload["student_id"], student_id)
                self.assertEqual(payload["display_name"], display_name)
                self.assertTrue(payload["csrf_token"])
                self.server.request(
                    "POST",
                    "/api/auth/logout",
                    cookie=cookie,
                    csrf=payload["csrf_token"],
                    origin="http://127.0.0.1:8000",
                )

    def test_unknown_demo_identity_is_rejected(self):
        response, cookie = self.server.login_demo("demo-unknown")
        self.assertEqual(response.status, 401)
        self.assertEqual(response.json(), {"error": "invalid_credentials"})
        self.assertIsNone(cookie)

    def test_demo_student_cannot_read_teacher_resources(self):
        _, cookie = self.server.login_demo("demo-zhang")
        for path in (
            "/api/teacher/students",
            "/api/teacher/export",
            "/api/teacher/stats",
        ):
            with self.subTest(path=path):
                response = self.server.request("GET", path, cookie=cookie)
                self.assertEqual(response.status, 403)
                self.assertEqual(response.json(), {"error": "forbidden"})
        anonymous = self.server.request("GET", "/api/teacher/export")
        self.assertEqual(anonymous.status, 401)
        self.assertEqual(anonymous.json(), {"error": "authentication_required"})

    def test_teacher_page_is_login_for_anonymous_and_403_for_student_sessions(self):
        anonymous = self.server.request("GET", "/teacher")
        self.assertEqual(anonymous.status, 200)
        self.assertIn("教师登录", anonymous.text)
        self.assertEqual(anonymous.headers["cache-control"], "no-store")

        for student_id in ("demo-zhang", "demo-li", "demo-wang", "demo-chen"):
            with self.subTest(student_id=student_id):
                _, cookie = self.server.login_demo(student_id)
                response = self.server.request("GET", "/teacher", cookie=cookie)
                self.assertEqual(response.status, 403)
                self.assertEqual(response.json(), {"error": "forbidden"})
                self.assertNotIn("教师登录", response.text)
                self.assertNotIn("教师工作台", response.text)
                self.assertEqual(response.headers["cache-control"], "no-store")

    def test_teacher_page_and_api_accept_real_teacher_session(self):
        login, cookie = self.server.login_teacher()
        self.assertEqual(login.status, 200)
        page = self.server.request("GET", "/teacher", cookie=cookie)
        self.assertEqual(page.status, 200)
        self.assertIn("教师登录", page.text)
        self.assertIn("待建设", page.text)
        self.assertEqual(page.headers["cache-control"], "no-store")

        api = self.server.request("GET", "/api/teacher/students", cookie=cookie)
        self.assertEqual(api.status, 200)
        self.assertEqual(api.json()["realm"], "real")

    def test_invalid_and_revoked_cookie_are_treated_as_anonymous_for_teacher_page(self):
        invalid = self.server.request(
            "GET", "/teacher", cookie="not-a-real-session"
        )
        self.assertEqual(invalid.status, 200)
        self.assertIn("教师登录", invalid.text)

        _, cookie = self.server.login_teacher()
        me = self.server.me(cookie).json()
        logout = self.server.request(
            "POST",
            "/api/auth/logout",
            cookie=cookie,
            csrf=me["csrf_token"],
            origin="http://127.0.0.1:8000",
        )
        self.assertEqual(logout.status, 200)
        revoked = self.server.request("GET", "/teacher", cookie=cookie)
        self.assertEqual(revoked.status, 200)
        self.assertIn("教师登录", revoked.text)

    def test_teacher_only_sees_authorised_class_and_realm(self):
        _, cookie = self.server.login_teacher()
        response = self.server.request(
            "GET",
            "/api/teacher/students?class_id=B&realm=demo&scope=all",
            cookie=cookie,
        )
        self.assertEqual(response.status, 200)
        payload = response.json()
        self.assertEqual(payload["realm"], "real")
        self.assertEqual(
            payload["students"],
            [
                {
                    "student_id": "real-a-1",
                    "display_name": "甲同学",
                    "class_id": "A",
                }
            ],
        )

    def test_teacher_session_is_real_realm_and_has_no_student_identity(self):
        _, cookie = self.server.login_teacher()
        payload = self.server.me(cookie).json()
        self.assertEqual(payload["realm"], "real")
        self.assertEqual(payload["class_ids"], ["A"])
        self.assertNotIn("student_id", payload)


if __name__ == "__main__":
    unittest.main()
