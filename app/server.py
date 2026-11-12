"""Minimal W4 foundation HTTP application built on the Python standard library."""

from __future__ import annotations

import hmac
import json
import mimetypes
import traceback
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import auth, config, db

APP_ROOT = Path(__file__).resolve().parent
PAGES_DIR = APP_ROOT / "pages"
STATIC_DIR = APP_ROOT / "static"


def _json_bytes(payload: object) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class AppHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        database: str | Path,
        origins: list[str],
        secure_cookie: bool,
    ) -> None:
        super().__init__(address, AppHandler)
        self.database = str(database)
        self.origins = {
            item.strip().rstrip("/") for item in origins if item.strip()
        }
        self.secure_cookie = secure_cookie


class AppHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "english-test-w4"

    # -- response helpers -------------------------------------------------
    def _send_bytes(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str,
        cache_control: str = "no-store",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache_control)
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_json(
        self,
        status: int,
        payload: object,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self._send_bytes(
            status,
            _json_bytes(payload),
            content_type="application/json; charset=utf-8",
            extra_headers=extra_headers,
        )

    def _send_html(self, status: int, body: str) -> None:
        self._send_bytes(
            status, body.encode("utf-8"), content_type="text/html; charset=utf-8"
        )

    def _session_cookie(self, token: str) -> str:
        parts = [
            f"{auth.SESSION_COOKIE}={token}",
            "HttpOnly",
            "SameSite=Strict",
            "Path=/",
            f"Max-Age={auth.SESSION_TTL_SECONDS}",
        ]
        if self.server.secure_cookie:
            parts.append("Secure")
        return "; ".join(parts)

    def _clear_session_cookie(self) -> str:
        parts = [
            f"{auth.SESSION_COOKIE}=",
            "HttpOnly",
            "SameSite=Strict",
            "Path=/",
            "Max-Age=0",
        ]
        if self.server.secure_cookie:
            parts.append("Secure")
        return "; ".join(parts)

    # -- request helpers --------------------------------------------------
    def _cookie_token(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            return None
        morsel = jar.get(auth.SESSION_COOKIE)
        return morsel.value if morsel is not None else None

    def _session(self) -> dict | None:
        return auth.resolve_session(self.server.database, self._cookie_token())

    def _read_json(self) -> dict:
        if self.headers.get("Transfer-Encoding"):
            # No chunked request bodies are accepted on this small API.
            raise ValueError("unsupported transfer encoding")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid content length") from exc
        if length < 0:
            raise ValueError("invalid content length")
        if length == 0:
            self._request_body_consumed = True
            return {}
        if length > 1024 * 1024:
            raise ValueError("request too large")
        raw = self.rfile.read(length)
        self._request_body_consumed = True
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("invalid json") from exc
        if not isinstance(payload, dict):
            raise ValueError("expected a json object")
        return payload

    def _drain_request_body(self) -> None:
        """Keep an HTTP/1.1 connection usable when a route ignores the body."""
        if getattr(self, "_request_body_consumed", False):
            return
        self._request_body_consumed = True
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            self.close_connection = True
            return
        if length < 0:
            self.close_connection = True
            return
        if length == 0:
            return
        if length > 1024 * 1024:
            self.close_connection = True
            return
        try:
            self.rfile.read(length)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _origin(self) -> str | None:
        value = self.headers.get("Origin")
        return value.strip() if value is not None else None

    def _origin_allowed(self, *, required: bool) -> bool:
        origin = self._origin()
        if origin is None:
            return not required
        if origin == "null":
            return False
        return origin.rstrip("/") in self.server.origins

    def _csrf_matches(self, session: dict) -> bool:
        supplied = self.headers.get("X-CSRF-Token")
        expected = session.get("csrf_token")
        if not supplied or not isinstance(expected, str):
            return False
        return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))

    def _require_session(self) -> dict | None:
        session = self._session()
        if session is None:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "authentication_required"})
            return None
        return session

    def _write_guard(self, session: dict) -> bool:
        if not self._origin_allowed(required=True) or not self._csrf_matches(session):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return False
        return True

    def _switch_guard(self) -> tuple[bool, dict | None]:
        """A login that replaces an existing cookie must prove the old session."""
        session = self._session()
        if session is None:
            return True, None
        if not self._origin_allowed(required=True) or not self._csrf_matches(session):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return False, None
        return True, session

    def _revoke(self, session: dict | None) -> None:
        if session is not None:
            auth.revoke_session(self.server.database, int(session["session_id"]))

    # -- routing ----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        try:
            self._route_get(urlsplit(self.path).path)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            traceback.print_exc()
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        self._request_body_consumed = False
        try:
            self._route_post(urlsplit(self.path).path)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            traceback.print_exc()
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
        finally:
            self._drain_request_body()

    def _route_get(self, path: str) -> None:
        if path == "/":
            self._send_bytes(
                HTTPStatus.FOUND,
                b"",
                content_type="text/plain; charset=utf-8",
                extra_headers={"Location": "/pad"},
            )
        elif path == "/health":
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "project_id": "english-test",
                    "schema_version": db.schema_version(self.server.database),
                },
            )
        elif path == "/api/capabilities":
            self._send_json(
                HTTPStatus.OK,
                {
                    "project_id": "english-test",
                    "capabilities": {
                        "face": {
                            "configured": False,
                            "status": "not_configured",
                            "reason": "no registered real camera or matching service",
                        },
                        "voice": {
                            "configured": False,
                            "status": "not_configured",
                            "reason": "no registered microphone evaluation service",
                        },
                        "audio": {
                            "configured": False,
                            "status": "not_configured",
                            "reason": "no verified UK/US human audio assets",
                        },
                    },
                },
            )
        elif path == "/api/demo/students":
            self._send_json(
                HTTPStatus.OK,
                {
                    "realm": "demo",
                    "students": [
                        {
                            "student_id": row["student_id"],
                            "display_name": row["display_name"],
                            "class_id": row["class_id"],
                        }
                        for row in db.DEMO_STUDENTS
                    ],
                },
            )
        elif path == "/api/me":
            self._handle_me()
        elif path == "/api/teacher/students":
            self._handle_teacher_students()
        elif path == "/api/teacher" or path.startswith("/api/teacher/"):
            self._handle_teacher_unimplemented()
        elif path == "/pad":
            self._serve_page("pad.html")
        elif path == "/teacher":
            self._serve_page("teacher.html")
        elif path.startswith("/static/"):
            self._serve_static(path.removeprefix("/static/"))
        elif path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def _route_post(self, path: str) -> None:
        if path == "/api/auth/teacher/login":
            self._handle_teacher_login()
        elif path == "/api/auth/demo/login":
            self._handle_demo_login()
        elif path == "/api/auth/logout":
            self._handle_logout()
        elif path == "/api/teacher" or path.startswith("/api/teacher/"):
            self._handle_teacher_unimplemented()
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    # -- handlers ---------------------------------------------------------
    def _handle_me(self) -> None:
        session = self._require_session()
        if session is None:
            return
        payload = {
            "role": session["role"],
            "realm": session["realm"],
            "display_name": session["display_name"],
            "class_ids": session["class_ids"],
            "csrf_token": session["csrf_token"],
        }
        if session["role"] == "student":
            payload["student_id"] = session["principal_id"]
        self._send_json(HTTPStatus.OK, payload)

    def _handle_teacher_login(self) -> None:
        try:
            body = self._read_json()
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        if not self._origin_allowed(required=False):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return
        allowed, previous = self._switch_guard()
        if not allowed:
            return
        username = body.get("username")
        supplied = body.get("password")
        if not isinstance(username, str) or not isinstance(supplied, str):
            self._send_json(
                HTTPStatus.UNAUTHORIZED, {"error": "invalid_credentials"}
            )
            return
        account = auth.authenticate_teacher(self.server.database, username, supplied)
        if account is None:
            self._send_json(
                HTTPStatus.UNAUTHORIZED, {"error": "invalid_credentials"}
            )
            return
        self._revoke(previous)
        issued = auth.issue_session(
            self.server.database,
            role="teacher",
            realm="real",
            principal_id=account["username"],
            display_name=account["display_name"],
            class_ids=account["class_ids"],
        )
        self._send_json(
            HTTPStatus.OK,
            {"ok": True},
            extra_headers={"Set-Cookie": self._session_cookie(issued["token"])},
        )

    def _handle_demo_login(self) -> None:
        try:
            body = self._read_json()
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        if not self._origin_allowed(required=False):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return
        allowed, previous = self._switch_guard()
        if not allowed:
            return
        student_id = body.get("student_id")
        if not isinstance(student_id, str):
            student_id = body.get("username")
        student = db.DEMO_BY_ID.get(student_id) if isinstance(student_id, str) else None
        if student is None:
            self._send_json(
                HTTPStatus.UNAUTHORIZED, {"error": "invalid_credentials"}
            )
            return
        self._revoke(previous)
        issued = auth.issue_session(
            self.server.database,
            role="student",
            realm="demo",
            principal_id=student["student_id"],
            display_name=student["display_name"],
            class_ids=[student["class_id"]],
        )
        self._send_json(
            HTTPStatus.OK,
            {"ok": True},
            extra_headers={"Set-Cookie": self._session_cookie(issued["token"])},
        )

    def _handle_logout(self) -> None:
        session = self._session()
        if session is not None and not self._write_guard(session):
            return
        self._revoke(session)
        self._send_json(
            HTTPStatus.OK,
            {"ok": True},
            extra_headers={"Set-Cookie": self._clear_session_cookie()},
        )

    def _handle_teacher_students(self) -> None:
        session = self._teacher_session()
        if session is None:
            return
        students = db.list_students_for_teacher(
            self.server.database,
            realm=session["realm"],
            class_ids=list(session["class_ids"]),
        )
        self._send_json(
            HTTPStatus.OK, {"realm": session["realm"], "students": students}
        )

    def _teacher_session(self) -> dict | None:
        session = self._require_session()
        if session is None:
            return None
        if session["role"] != "teacher" or session["realm"] != "real":
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return None
        return session

    def _handle_teacher_unimplemented(self) -> None:
        session = self._teacher_session()
        if session is None:
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    # -- static pages -----------------------------------------------------
    def _serve_page(self, name: str) -> None:
        path = PAGES_DIR / name
        if not path.is_file():
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "page_missing"})
            return
        self._send_html(HTTPStatus.OK, path.read_text(encoding="utf-8"))

    def _serve_static(self, relative: str) -> None:
        candidate = (STATIC_DIR / relative).resolve()
        root = STATIC_DIR.resolve()
        if root not in candidate.parents or not candidate.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self._send_bytes(
            HTTPStatus.OK,
            candidate.read_bytes(),
            content_type=f"{content_type}; charset=utf-8"
            if content_type.startswith("text/")
            else content_type,
            cache_control="public, max-age=300",
        )

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


def create_server(
    host: str = "0.0.0.0",
    port: int = 8000,
    *,
    database: str | Path | None = None,
    origins: list[str] | None = None,
    secure_cookie: bool | None = None,
) -> AppHTTPServer:
    location = Path(database) if database is not None else config.database_path()
    db.migrate(location)
    return AppHTTPServer(
        (host, port),
        database=location,
        origins=list(config.allowed_origins() if origins is None else origins),
        secure_cookie=config.secure_cookies() if secure_cookie is None else secure_cookie,
    )


def main() -> None:
    server = create_server(config.server_host(), config.server_port())
    print(
        f"english-test W4 listening on http://{server.server_address[0]}:"
        f"{server.server_address[1]}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
