# Copyright (c), CommunityLogiq Software

import base64
import contextlib
import gzip
import http.server
import io
import threading
import uuid
from typing import Callable, Iterator
from unittest.mock import patch

import pytest
import requests

from ..api.drive import get_file_stream
from ..api_key_context import SIGNATURE_V1, ApiKeyContext
from ..keys import Environment, Key, Region
from ..request_context import STREAM_BLOCK_SIZE, RequestContext
from ..types.id import ObjectId

PATH = "/v1/api/ulv2/drive/file/1234"
WAIT_SECONDS = 10


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.requests.append((self.path, self.headers))  # type: ignore
        self.server.respond(self)  # type: ignore

    def log_message(self, format, *args):
        pass


def _send(handler: _Handler, status: int, body: bytes, **headers: str):
    handler.send_response(status)
    for name, value in headers.items():
        handler.send_header(name.replace("_", "-"), value)
    handler.send_header("content-length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


@contextlib.contextmanager
def _serve(respond: Callable[[_Handler], None]) -> Iterator[http.server.HTTPServer]:
    """Answer the GET requests of an API key context with `respond`."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.respond = respond  # type: ignore
    server.requests = []  # type: ignore
    base = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with patch(
            "ulsdk.api_key_context._get_endpoint", lambda region, env, path: base + path
        ):
            yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _context() -> ApiKeyContext:
    secret = base64.b64encode(bytes(range(32))).decode()
    key = Key(uuid.uuid4(), Region.US, "test-access-key", secret)
    return ApiKeyContext(key, Environment.Prod)


def _body(size: int) -> bytes:
    return bytes(i % 251 for i in range(size))


def test_get_stream_reads_the_body_in_parts():
    body = _body(2 * STREAM_BLOCK_SIZE + 17)
    read_first_part = threading.Event()
    waited = []

    def respond(handler: _Handler):
        handler.send_response(200)
        handler.send_header("content-length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body[:STREAM_BLOCK_SIZE])
        handler.wfile.flush()
        # A client that reads the complete body first never sets the event.
        waited.append(read_first_part.wait(WAIT_SECONDS))
        handler.wfile.write(body[STREAM_BLOCK_SIZE:])

    with _serve(respond) as server:
        with _context().get_stream(PATH, params={"a": "b c"}) as stream:
            head = stream.read(1000)
            read_first_part.set()
            tail = stream.read()

    assert head + tail == body
    assert waited == [True]
    path, headers = server.requests[0]  # type: ignore
    assert path == PATH + "?a=b+c"
    assert headers["authorization"].startswith(SIGNATURE_V1)


def test_get_stream_returns_blocks_of_the_requested_size():
    body = _body(STREAM_BLOCK_SIZE + 5)
    size = STREAM_BLOCK_SIZE // 2 + 1

    with _serve(lambda handler: _send(handler, 200, body)):
        with _context().get_stream(PATH) as stream:
            blocks = list(iter(lambda: stream.read(size), b""))

    assert [len(block) for block in blocks] == [size, size, 3]
    assert b"".join(blocks) == body


def test_get_stream_decodes_a_compressed_body():
    body = _body(STREAM_BLOCK_SIZE + 5)
    packed = gzip.compress(body)

    with _serve(lambda handler: _send(handler, 200, packed, content_encoding="gzip")):
        with _context().get_stream(PATH) as stream:
            assert stream.read() == body


def test_get_stream_reads_an_empty_body():
    with _serve(lambda handler: _send(handler, 200, b"")):
        with _context().get_stream(PATH) as stream:
            assert stream.read() == b""


def test_get_stream_fails_on_a_short_body():
    body = _body(STREAM_BLOCK_SIZE)

    def respond(handler: _Handler):
        handler.send_response(200)
        handler.send_header("content-length", str(2 * len(body)))
        handler.end_headers()
        handler.wfile.write(body)
        handler.close_connection = True

    with _serve(respond):
        with _context().get_stream(PATH) as stream:
            with pytest.raises(requests.RequestException):
                stream.read()


def test_get_stream_keeps_the_body_of_an_error():
    message = b'{"code": 404, "message": "no such file"}'

    with _serve(lambda handler: _send(handler, 404, message)):
        with pytest.raises(requests.HTTPError) as error:
            _context().get_stream(PATH)

    assert error.value.response.status_code == 404
    assert error.value.response.content == message


def test_get_stream_rejects_a_redirect_that_is_not_followed():
    def respond(handler: _Handler):
        _send(handler, 302, b"moved", location="/elsewhere")

    with _serve(respond):
        with pytest.raises(requests.HTTPError) as error:
            _context().get_stream(PATH, allow_redirects=False)

    assert error.value.response.status_code == 302


def test_get_stream_close_stops_the_download():
    stopped = threading.Event()

    def respond(handler: _Handler):
        handler.send_response(200)
        handler.send_header("content-length", str(1 << 40))
        handler.end_headers()
        block = bytes(STREAM_BLOCK_SIZE)
        try:
            while True:
                handler.wfile.write(block)
        except OSError:
            stopped.set()
        handler.close_connection = True

    with _serve(respond):
        stream = _context().get_stream(PATH)
        assert stream.read(10) == bytes(10)
        stream.close()
        assert stopped.wait(WAIT_SECONDS)

    assert stream.closed
    with pytest.raises(ValueError):
        stream.read(1)


class _BufferedContext(RequestContext):
    """A context without its own `get_stream`."""

    def __init__(self):
        self.calls = []

    def get(self, path, params=None, headers=None, **kwargs):
        self.calls.append((path, params, headers, kwargs))
        return b"content"

    def put(self, path, body=None, mimetype="", params=None, headers=None, **kwargs):
        raise NotImplementedError

    def post(self, path, body=None, mimetype="", params=None, headers=None, **kwargs):
        raise NotImplementedError

    def upload(self, path, files, params=None, headers=None):
        raise NotImplementedError

    def delete(self, path, params=None, headers=None, **kwargs):
        raise NotImplementedError

    def connect(self, path, params=None, headers=None):
        raise NotImplementedError


def test_default_get_stream_reads_the_complete_body():
    ctx = _BufferedContext()

    with ctx.get_stream(PATH, {"a": "b"}, {"c": "d"}, timeout=5) as stream:
        assert stream.read(3) == b"con"
        assert stream.read() == b"tent"

    assert ctx.calls == [(PATH, {"a": "b"}, {"c": "d"}, {"timeout": 5})]


def test_get_file_stream_passes_the_request_options():
    calls = []

    class Context(_BufferedContext):
        def get_stream(self, path, params=None, headers=None, **kwargs):
            calls.append((path, kwargs))
            return io.BytesIO(b"content")

    id = uuid.UUID(int=7)
    with get_file_stream(Context(), ObjectId.from_uuid(id), timeout=(1, 2)) as stream:
        assert stream.read() == b"content"

    assert calls == [(f"/v1/api/ulv2/drive/file/{id}", {"timeout": (1, 2)})]
