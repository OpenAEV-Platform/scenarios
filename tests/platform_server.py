"""A local HTTP server that stands in for the OpenAEV platform in tests.

Each test sets the answer the platform gives; the server records every request it receives, so
a test can check what was sent, and that nothing was sent when it must not be.
"""

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class Received:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


@dataclass
class Platform:
    url: str
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    delay: float = 0.0
    drip: float = 0.0  # seconds between two bytes of the body, for a platform that crawls
    raw: bytes = b""  # sent as it is instead of a well-formed answer, dripped too
    received: list[Received] = field(default_factory=list)

    def answer(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.status, self.body, self.headers = status, body, headers or {}


def _handler(platform: Platform) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _respond(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            platform.received.append(
                Received(
                    self.command,
                    self.path,
                    {key.lower(): value for key, value in self.headers.items()},
                    self.rfile.read(length),
                )
            )
            time.sleep(platform.delay)
            try:
                if platform.raw:
                    for byte in platform.raw:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(platform.drip)
                    return
                self.send_response(platform.status)
                for key, value in platform.headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(platform.body)))
                self.end_headers()
                if platform.drip:
                    for byte in platform.body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(platform.drip)
                else:
                    self.wfile.write(platform.body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the client gave up first, as a test may expect

        # The names the base class dispatches on; CONNECT is what a proxy receives for HTTPS.
        do_GET = do_POST = do_CONNECT = _respond  # noqa: N815

        def log_message(self, *args: object) -> None:
            pass  # quiet: the tests read what was received

    return Handler


@contextmanager
def platform_server(host: str = "127.0.0.1") -> Iterator[Platform]:
    server = ThreadingHTTPServer((host, 0), _handler(Platform("")))
    platform = Platform(f"http://{host}:{server.server_address[1]}")
    server.RequestHandlerClass = _handler(platform)
    thread = threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True)
    thread.start()
    try:
        yield platform
    finally:
        server.shutdown()
        server.server_close()
