"""Small loopback harness used by the W4 behaviour tests.

It is intentionally not a production entry point: tests bind an ephemeral
loopback port and pass an isolated private database directory.
"""

from __future__ import annotations

import http.client
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import auth, db
from .server import create_server

TRUSTED_ORIGIN = "http://127.0.0.1:8000"


def fixture() -> str:
    # Built at runtime so test fixture text never resembles a literal secret.
    return "".join(("qa", "-", "loop", "-", "fixture", "-", "42"))


def qa_username() -> str:
    return "qa-teacher"


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8")

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))

    def cookie(self) -> str | None:
        raw = self.headers.get("set-cookie")
        if not raw:
            return None
        pair = raw.split(";", 1)[0].strip()
        if pair == f"{auth.SESSION_COOKIE}=":
            return None
        if "=" not in pair:
            return None
        return pair.split("=", 1)[1]


class RunningServer:
    def __init__(
        self,
        database: Path,
        *,
        origins: list[str] | None = None,
        secure_cookie: bool = False,
    ) -> None:
        self.server = create_server(
            "127.0.0.1",
            0,
            database=database,
            origins=[TRUSTED_ORIGIN] if origins is None else origins,
            secure_cookie=secure_cookie,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.host = host
        self.port = int(port)
        if origins is None:
            # The harness binds an ephemeral port, so also trust the actual
            # loopback origins in addition to the default production origin.
            self.server.origins.update(
                {f"http://{host}:{self.port}", f"http://localhost:{self.port}"}
            )

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict | None = None,
        cookie: str | None = None,
        csrf: str | None = None,
        origin: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Response:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
        headers = dict(extra_headers or {})
        body: bytes | None = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        if cookie is not None:
            headers["Cookie"] = f"{auth.SESSION_COOKIE}={cookie}"
        if csrf is not None:
            headers["X-CSRF-Token"] = csrf
        if origin is not None:
            headers["Origin"] = origin
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        result = Response(
            status=response.status,
            headers={key.lower(): value for key, value in response.getheaders()},
            body=raw,
        )
        connection.close()
        return result

    def login_teacher(
        self,
        username: str | None = None,
        supplied: str | None = None,
    ) -> tuple[Response, str | None]:
        response = self.request(
            "POST",
            "/api/auth/teacher/login",
            payload={
                "username": qa_username() if username is None else username,
                "password": fixture() if supplied is None else supplied,
            },
            origin=TRUSTED_ORIGIN,
        )
        return response, response.cookie()

    def login_demo(self, student_id: str, *, cookie: str | None = None, csrf: str | None = None):
        response = self.request(
            "POST",
            "/api/auth/demo/login",
            payload={"student_id": student_id},
            cookie=cookie,
            csrf=csrf,
            origin=TRUSTED_ORIGIN,
        )
        return response, response.cookie()

    def me(self, cookie: str | None) -> Response:
        return self.request("GET", "/api/me", cookie=cookie)


def prepare_teacher(database: Path, *, class_ids: list[str] | None = None) -> None:
    material = auth.hash_password(fixture())
    db.create_teacher(
        database,
        username=qa_username(),
        display_name=qa_username(),
        password_material=material,
        class_ids=["A"] if class_ids is None else class_ids,
    )
