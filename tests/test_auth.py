"""Authentication, session and CSRF behaviour for the W4 foundation."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from app import auth, db
from app.testkit import TRUSTED_ORIGIN, RunningServer, prepare_teacher, fixture, qa_username


class AuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.database = Path(self.tmp.name) / "vocab.sqlite3"
        db.migrate(self.database)
        prepare_teacher(self.database)
        self.server = RunningServer(self.database)

    def tearDown(self) -> None:
        self.server.close()
        self.tmp.cleanup()

    def test_password_material_is_salted_pbkdf2_with_original_iterations(self):
        material = auth.hash_password(fixture())
        connection = db.connect(self.database)
        try:
            row = connection.execute(
                "SELECT * FROM teachers WHERE username = ?", (qa_username(),)
            ).fetchone()
        finally:
            connection.close()
        self.assertIsNotNone(row)
        self.assertNotEqual(row["password_hash"], fixture())
        self.assertEqual(len(row["password_salt"]), 32)
        self.assertEqual(int(row["password_iterations"]), 240000)
        self.assertTrue(
            auth.verify_password(
                fixture(),
                password_hash=row["password_hash"],
                password_salt=row["password_salt"],
                password_iterations=row["password_iterations"],
            )
        )
        self.assertFalse(
            auth.verify_password(
                material["password_hash"],
                password_hash=row["password_hash"],
                password_salt=row["password_salt"],
                password_iterations=row["password_iterations"],
            )
        )

    def test_unknown_account_and_wrong_credential_both_return_invalid_credentials(self):
        wrong_value = "".join(("not", "-", "the", "-", "fixture"))
        wrong, wrong_cookie = self.server.login_teacher(None, wrong_value)
        self.assertEqual(wrong.status, 401)
        self.assertEqual(wrong.json(), {"error": "invalid_credentials"})
        self.assertIsNone(wrong_cookie)

        missing, missing_cookie = self.server.login_teacher(
            "no-such-teacher", wrong_value
        )
        self.assertEqual(missing.status, 401)
        self.assertEqual(missing.json(), {"error": "invalid_credentials"})
        self.assertIsNone(missing_cookie)

    def test_login_sets_hardened_cookie_and_me_contract(self):
        response, cookie = self.server.login_teacher()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.json(), {"ok": True})
        self.assertIsNotNone(cookie)
        set_cookie = response.headers["set-cookie"].lower()
        self.assertIn("httponly", set_cookie)
        self.assertIn("samesite=strict", set_cookie)
        self.assertIn("path=/", set_cookie)
        self.assertNotIn("secure", set_cookie)

        me = self.server.me(cookie)
        self.assertEqual(me.status, 200)
        self.assertEqual(me.headers["cache-control"], "no-store")
        payload = me.json()
        self.assertEqual(payload["role"], "teacher")
        self.assertEqual(payload["realm"], "real")
        self.assertEqual(payload["display_name"], qa_username())
        self.assertEqual(payload["class_ids"], ["A"])
        self.assertTrue(payload["csrf_token"])
        self.assertNotIn("student_id", payload)

    def test_anonymous_me_is_401_and_no_store(self):
        response = self.server.me(None)
        self.assertEqual(response.status, 401)
        self.assertEqual(response.json(), {"error": "authentication_required"})
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_logout_requires_csrf_then_revokes_persisted_session(self):
        _, cookie = self.server.login_teacher()
        me = self.server.me(cookie).json()

        refused = self.server.request(
            "POST",
            "/api/auth/logout",
            cookie=cookie,
            origin=TRUSTED_ORIGIN,
        )
        self.assertEqual(refused.status, 403)
        self.assertEqual(refused.json(), {"error": "forbidden"})
        self.assertEqual(self.server.me(cookie).status, 200)

        logged_out = self.server.request(
            "POST",
            "/api/auth/logout",
            cookie=cookie,
            csrf=me["csrf_token"],
            origin=TRUSTED_ORIGIN,
        )
        self.assertEqual(logged_out.status, 200)
        self.assertEqual(logged_out.json(), {"ok": True})
        self.assertIn("max-age=0", logged_out.headers["set-cookie"].lower())
        self.assertEqual(self.server.me(cookie).status, 401)

        connection = db.connect(self.database)
        try:
            row = connection.execute(
                "SELECT revoked_at FROM sessions WHERE token_digest = ?",
                (auth.token_digest(cookie),),
            ).fetchone()
        finally:
            connection.close()
        self.assertIsNotNone(row)
        self.assertIsNotNone(row["revoked_at"])

    def test_expired_session_is_rejected(self):
        _, cookie = self.server.login_teacher()
        connection = db.connect(self.database)
        try:
            connection.execute(
                "UPDATE sessions SET expires_at = ? WHERE token_digest = ?",
                (int(time.time()) - 1, auth.token_digest(cookie)),
            )
        finally:
            connection.close()
        response = self.server.me(cookie)
        self.assertEqual(response.status, 401)
        self.assertEqual(response.json(), {"error": "authentication_required"})

    def test_student_private_paths_reject_expired_and_revoked_cookies(self):
        _, expired_cookie = self.server.login_demo("demo-zhang")
        connection = db.connect(self.database)
        try:
            connection.execute(
                "UPDATE sessions SET expires_at = ? WHERE token_digest = ?",
                (int(time.time()) - 1, auth.token_digest(expired_cookie)),
            )
        finally:
            connection.close()
        expired = self.server.request(
            "GET", "/api/student/tasks", cookie=expired_cookie
        )
        self.assertEqual(expired.status, 401)
        self.assertEqual(expired.json(), {"error": "authentication_required"})

        _, revoked_cookie = self.server.login_demo("demo-li")
        revoked_me = self.server.me(revoked_cookie).json()
        logout = self.server.request(
            "POST",
            "/api/auth/logout",
            cookie=revoked_cookie,
            csrf=revoked_me["csrf_token"],
            origin=TRUSTED_ORIGIN,
        )
        self.assertEqual(logout.status, 200)
        revoked = self.server.request(
            "GET", "/api/student/tasks", cookie=revoked_cookie
        )
        self.assertEqual(revoked.status, 401)
        self.assertEqual(revoked.json(), {"error": "authentication_required"})

    def test_switching_session_requires_current_csrf_and_revokes_old_cookie(self):
        _, first_cookie = self.server.login_teacher()
        first_me = self.server.me(first_cookie).json()

        refused, refused_cookie = self.server.login_demo("demo-zhang", cookie=first_cookie)
        self.assertEqual(refused.status, 403)
        self.assertIsNone(refused_cookie)
        self.assertEqual(self.server.me(first_cookie).status, 200)

        switched, second_cookie = self.server.login_demo(
            "demo-zhang", cookie=first_cookie, csrf=first_me["csrf_token"]
        )
        self.assertEqual(switched.status, 200)
        self.assertEqual(switched.json(), {"ok": True})
        self.assertIsNotNone(second_cookie)
        self.assertEqual(self.server.me(first_cookie).status, 401)
        second_me = self.server.me(second_cookie).json()
        self.assertEqual(second_me["role"], "student")
        self.assertEqual(second_me["realm"], "demo")
        self.assertEqual(second_me["student_id"], "demo-zhang")

    def test_login_rejects_cross_origin_and_null_origin(self):
        cross = self.server.request(
            "POST",
            "/api/auth/teacher/login",
            payload={"username": qa_username(), "password": fixture()},
            origin="https://evil.example",
        )
        self.assertEqual(cross.status, 403)
        self.assertEqual(cross.json(), {"error": "forbidden"})
        self.assertIsNone(cross.cookie())

        null_origin = self.server.request(
            "POST",
            "/api/auth/teacher/login",
            payload={"username": qa_username(), "password": fixture()},
            origin="null",
        )
        self.assertEqual(null_origin.status, 403)
        self.assertIsNone(null_origin.cookie())


if __name__ == "__main__":
    unittest.main()
