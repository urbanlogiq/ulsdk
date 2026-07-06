# Copyright (c), CommunityLogiq Software

import base64
import uuid
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

import nacl.encoding
import nacl.signing

from ..api_key_context import (
    REQUEST_TYPE,
    SIGNATURE_V1,
    ApiKeyContext,
    canonicalize_request,
)
from ..keys import Environment, Key, Region


class _FakeResponse:
    content = b""
    headers: dict = {}

    def raise_for_status(self):
        pass


def _make_key(seed: bytes) -> Key:
    return Key(
        uuid.uuid4(),
        Region.US,
        "test-access-key",
        base64.b64encode(seed).decode(),
    )


def test_post_percent_encodes_path_and_signs_decoded_path():
    seed = bytes(range(32))
    key = _make_key(seed)
    ctx = ApiKeyContext(key, Environment.Prod)

    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        # copy_headers clears this dict after the response, so snapshot it
        captured["headers"] = dict(kwargs["headers"])
        return _FakeResponse()

    raw_path = "/v1/api/ulv2/drive/1234/Report #7 50%.pdf"
    params = {"ty": "file", "mime": "application/pdf", "chunks": "1"}
    with patch("ulsdk.api_key_context.requests.post", fake_post):
        ctx.post(raw_path, body=b"", mimetype="text/plain", params=params)

    split = urlsplit(captured["url"])
    # reserved characters must be encoded so nothing is parsed as fragment/query
    assert split.fragment == ""
    assert "#" not in split.path
    assert " " not in split.path
    assert unquote(split.path) == raw_path

    # the gateway verifies the signature over the *decoded* wire path; replay
    # its canonicalization and check the signature we sent actually verifies
    headers = captured["headers"]
    request_hash = canonicalize_request(
        "POST", unquote(split.path), params, headers, ["x-ul-date"], b""
    )
    scope = f"{key.user_id}/{headers['x-ul-date']}/{key.region.str()}/{REQUEST_TYPE}"
    signing_string = f"{SIGNATURE_V1}\n{scope}\n{request_hash}"
    signature = headers["authorization"].split("Signature=")[1]

    verify_key = nacl.signing.SigningKey(
        seed, encoder=nacl.encoding.RawEncoder
    ).verify_key
    verify_key.verify(signing_string.encode("utf8"), bytes.fromhex(signature))


def test_get_plain_path_is_unchanged():
    key = _make_key(bytes(range(32)))
    ctx = ApiKeyContext(key, Environment.Prod)

    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        return _FakeResponse()

    with patch("ulsdk.api_key_context.requests.get", fake_get):
        ctx.get("/v1/api/ulv2/drive/1234/plain-name.csv")

    assert captured["url"].endswith("/v1/api/ulv2/drive/1234/plain-name.csv")
