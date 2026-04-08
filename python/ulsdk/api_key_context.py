# Copyright (c), CommunityLogiq Software

import base64
import hashlib
import time
import urllib.parse
import uuid
from typing import Dict, List, Optional, Union, cast

import nacl.encoding
import nacl.signing
import requests
from requests import Request, Session
from websockets.sync.client import ClientConnection, connect

from .keys import Environment, Key, Region
from .request_context import File, RequestContext, _get_endpoint

REQUEST_TYPE = "ul1_request"
SIGNATURE_V1 = "UL1-ED25519"


def canonicalize_path(path: str) -> str:
    """Add "/" if path doesn't start with it"""
    return path if path.startswith("/") else f"/{path}"


def canonicalize_query_string(query: Optional[Dict[str, str]]) -> str:
    if query is None:
        return ""

    components: List[str] = []
    for k in query:
        if k == "X-UL-Signature":
            continue
        components.append(k + "=" + urllib.parse.quote_plus(query[k]))

    return "&".join(sorted(components))


def canonicalize_headers(signed_headers: List[str], headers: Dict[str, str]) -> str:
    sorted_signed_headers = list(sorted(signed_headers))
    canonical_header_parts = []
    for v in sorted_signed_headers:
        value = headers[v]
        canonical_header_parts.append(v.lower() + ":" + value.strip())

    return "\n".join(canonical_header_parts)


def hash(b: bytes) -> str:
    m = hashlib.sha256()
    m.update(b)
    return m.digest().hex()


def canonicalize_request(
    method: str,
    path: str,
    query: Optional[Dict[str, str]],
    headers: Dict[str, str],
    signed_headers: List[str],
    body: Optional[bytes],
) -> str:
    canonical_path = canonicalize_path(path)
    canonical_query_string = canonicalize_query_string(query)
    canonical_headers = canonicalize_headers(signed_headers, headers)

    s = (
        method.upper()
        + "\n"
        + canonical_path
        + "\n"
        + canonical_query_string
        + "\n"
        + canonical_headers
        + "\n"
        + ";".join(sorted(signed_headers))
        + "\n"
        + hash(b"" if body is None else body)
    )

    return hash(s.encode("utf8"))


def _generate_auth_header(
    key: Key,
    method: str,
    path: str,
    query: Optional[Dict[str, str]],
    headers: Dict[str, str],
    body: Optional[bytes],
):
    ts = int(time.time())
    signed_headers = ["x-ul-date"]
    headers["x-ul-date"] = str(ts)

    request_hash = canonicalize_request(
        method, path, query, headers, signed_headers, body
    )
    scope = f"{key.user_id}/{ts}/{key.region.str()}/{REQUEST_TYPE}"

    signing_string = SIGNATURE_V1 + "\n" + scope + "\n" + request_hash
    signing_key = base64.b64decode(key.secret_key + "==")
    nacl_key = nacl.signing.SigningKey(
        signing_key[0:32], encoder=nacl.encoding.RawEncoder
    )
    signature = nacl_key.sign(signing_string.encode("utf8")).signature.hex()

    auth_header_value = "{} Credential={}/{}, SignedHeaders={}, Signature={}".format(
        SIGNATURE_V1,
        key.access_key,
        scope,
        ";".join(signed_headers),
        signature,
    )
    headers["authorization"] = auth_header_value

    return headers


def copy_headers(src, dest: Dict[str, str]):
    dest.clear()
    for k in src:
        dest[k] = src[k]


class ApiKeyContext(RequestContext):
    def __init__(
        self,
        key: Key,
        environment: Environment,
    ):
        self._key = key
        self._environment = environment

    def user_id(self) -> uuid.UUID:
        return self._key.user_id

    def env(self) -> Environment:
        return self._environment

    def region(self) -> Region:
        return self._key.region

    def get(
        self,
        path: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> bytes:
        if params is None:
            params = dict()

        if headers is None:
            headers = dict()

        endpoint = _get_endpoint(self._key.region, self._environment, path)
        headers = _generate_auth_header(self._key, "GET", path, params, headers, None)
        kwargs["headers"] = headers
        kwargs["params"] = params
        response = requests.get(endpoint, **kwargs)
        copy_headers(response.headers, headers)
        response.raise_for_status()
        return response.content

    def put(
        self,
        path: str,
        body: Union[bytes, str, None] = None,
        mimetype: str = "application/octet-stream",
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> bytes:
        if params is None:
            params = dict()

        if headers is None:
            headers = dict()

        endpoint = _get_endpoint(self._key.region, self._environment, path)
        if mimetype is None:
            mimetype = (
                "application/json" if type(body) is str else "application/octet-stream"
            )
        data_as_bytes = cast(
            bytes, cast(str, body).encode("utf8") if type(body) is str else body
        )
        headers["content-type"] = mimetype
        headers["content-length"] = str(len(data_as_bytes))
        headers = _generate_auth_header(
            self._key, "PUT", path, params, headers, data_as_bytes
        )
        kwargs["headers"] = headers
        kwargs["data"] = body
        kwargs["params"] = params
        response = requests.put(endpoint, **kwargs)
        copy_headers(response.headers, headers)
        response.raise_for_status()
        return response.content

    def post(
        self,
        path: str,
        body: Union[bytes, str, None] = None,
        mimetype: str = "application/octet-stream",
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> bytes:
        if params is None:
            params = dict()

        if headers is None:
            headers = dict()

        endpoint = _get_endpoint(self._key.region, self._environment, path)
        if mimetype is None:
            mimetype = (
                "application/json" if type(body) is str else "application/octet-stream"
            )
        data_as_bytes = cast(
            bytes, cast(str, body).encode("utf8") if type(body) is str else body
        )
        headers["content-type"] = mimetype
        headers["content-length"] = (
            str(len(data_as_bytes)) if data_as_bytes is not None else "0"
        )
        headers = _generate_auth_header(
            self._key, "POST", path, params, headers, data_as_bytes
        )
        kwargs["headers"] = headers
        kwargs["data"] = body
        kwargs["params"] = params
        response = requests.post(endpoint, **kwargs)
        copy_headers(response.headers, headers)
        response.raise_for_status()
        return response.content

    def upload(
        self,
        path: str,
        files: List[File],
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> bytes:
        if params is None:
            params = dict()

        if headers is None:
            headers = dict()

        endpoint = _get_endpoint(self._key.region, self._environment, path)
        file_dict = {f.name: (f.name, f.data, f.mimetype) for f in files}

        kwargs = {"files": file_dict}

        s = Session()

        req = Request("POST", endpoint, **kwargs)
        prepped = req.prepare()

        file_hashes = []

        for file in files:
            file_hash = hash(file.data)
            file_hashes.append(f"{file.name}={file_hash}")
        file_hash_header_value = ", ".join(file_hashes)

        headers["x-ul-file-hash"] = file_hash_header_value

        body_data = prepped.body
        data_as_bytes = (
            cast(
                bytes,
                cast(str, body_data).encode("utf8")
                if type(body_data) is str
                else body_data,
            )
            if body_data is not None
            else None
        )
        headers = _generate_auth_header(
            self._key, "POST", path, params, headers, data_as_bytes
        )

        # We need to preserve the prepped headers because they contain the correct content-length and content-type.
        # The content type contains the boundary string that forms part of the request body.
        # We end up with our custom headers, plus also the content-type and content-length from the prepped request.
        headers.update(prepped.headers)

        # The following is type-ignored because the typing for PreparedRequest.headers is CaseInsensitiveDict[str],
        # and that type is declared within the requests library and not exported.
        prepped.headers = headers  # type: ignore

        # Add query parameters to the prepared request
        if params:
            prepped.prepare_url(endpoint, params)

        res = s.send(prepped)
        res.raise_for_status()
        return res.content

    def delete(
        self,
        path: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> bytes:
        if params is None:
            params = dict()

        if headers is None:
            headers = dict()

        endpoint = _get_endpoint(self._key.region, self._environment, path)
        headers = _generate_auth_header(
            self._key, "DELETE", path, params, headers, None
        )
        kwargs["headers"] = headers
        kwargs["params"] = params
        response = requests.delete(endpoint, **kwargs)
        copy_headers(response.headers, headers)
        response.raise_for_status()
        return response.content

    def connect(
        self,
        path: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> ClientConnection:
        if params is None:
            params = dict()

        if headers is None:
            headers = dict()

        endpoint = _get_endpoint(self._key.region, self._environment, path).replace(
            "https", "wss"
        )
        headers = _generate_auth_header(self._key, "GET", path, params, headers, None)
        if params is not None:
            params_str = canonicalize_query_string(params)
            endpoint = endpoint + "?" + params_str

        connection = connect(endpoint, additional_headers=headers)
        return connection
