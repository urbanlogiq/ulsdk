# Copyright (c), CommunityLogiq Software

import io
import uuid
from abc import ABC, abstractmethod
from typing import BinaryIO, Dict, List, Mapping, NamedTuple, Optional, Union
from urllib.parse import quote

import requests
from websockets.sync.client import ClientConnection

from .keys import Environment, Region


def _get_endpoint(region: Region, environment: Environment, api: str) -> str:
    base = None
    match (region, environment):
        case (Region.CA, Environment.Prod):
            base = "https://home.urbanlogiq.ca"
        case (Region.CA, Environment.Stage):
            base = "https://stage.urbanlogiq.ca"
        case (Region.US, Environment.Prod):
            base = "https://home.urbanlogiq.us"
        case (Region.US, Environment.Stage):
            base = "https://stage.urbanlogiq.us"
        case _:
            raise ValueError(f"Unknown region/environment: {region}/{environment}")

    # Encode reserved chars (e.g. "#" in a drive entry name) for the wire only;
    # signatures are computed over the raw path, which the gateway decodes back to.
    return f"{base}{quote(api, safe='/')}"


class File(NamedTuple):
    name: str
    mimetype: str
    data: bytes


STREAM_BLOCK_SIZE = 1024 * 1024


class _ResponseReader(io.RawIOBase):
    """Read the body of a response in blocks. Close the response with the
    reader."""

    def __init__(self, response: requests.Response):
        self._response = response
        # Decode the body as `Response.content` does.
        self._blocks = response.iter_content(STREAM_BLOCK_SIZE)
        self._block = memoryview(b"")

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        while not self._block:
            block = next(self._blocks, None)
            if block is None:
                self._check_length()
                return 0
            self._block = memoryview(block)

        with memoryview(buffer).cast("B") as target:
            count = min(len(target), len(self._block))
            target[:count] = self._block[:count]
        self._block = self._block[count:]
        return count

    def _check_length(self) -> None:
        """Fail if the body is shorter than the response declared. Not all
        versions of the HTTP library do this check."""
        declared = self._response.headers.get("content-length")
        if declared is None or not declared.isdigit():
            return
        received = self._response.raw.tell()
        if received < int(declared):
            raise requests.ConnectionError(
                f"The response ended after {received} of {declared} bytes",
                response=self._response,
            )

    def close(self) -> None:
        self._response.close()
        super().close()


class ResponseStream(io.BufferedReader):
    """The body of a response as a readable binary stream, with the status
    and the headers of the response. Closing the stream closes the response."""

    def __init__(self, response: requests.Response):
        super().__init__(_ResponseReader(response), STREAM_BLOCK_SIZE)
        self.status_code: int = response.status_code
        # The names are not case-sensitive.
        self.headers: Mapping[str, str] = response.headers


def response_stream(response: requests.Response) -> ResponseStream:
    """Return the body of a response as a readable binary stream. The request
    must have `stream=True`.

    Raise an error for a status that is not a success. A redirect that the
    request did not follow has no content."""
    if 200 <= response.status_code < 300:
        return ResponseStream(response)

    try:
        # Keep the error body for the caller, as the other requests do.
        _ = response.content
    finally:
        response.close()
    response.raise_for_status()
    raise requests.HTTPError(
        f"{response.status_code} is not a success status for url: {response.url}",
        response=response,
    )


# A RequestContext is a superclass that enables code to use either signed
# requests-with-api-keys, bearer tokens, or other authentication schemes.

class RequestContext(ABC):
    def user_id(self) -> uuid.UUID:
        """Return the user ID of the context, if available"""
        raise NotImplementedError

    def region(self) -> Region:
        """Return the region of the context, if available"""
        raise NotImplementedError

    def env(self) -> Environment:
        """Return the environment of the context, if available"""
        raise NotImplementedError

    @abstractmethod
    def get(
        self,
        path: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> bytes:
        """Make a GET request to the given path with optional parameters and headers"""

    def get_stream(
        self,
        path: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> BinaryIO:
        """Make a GET request to the given path and return the response body as
        a readable binary stream. Close the stream after use.

        This default reads the complete body into memory. Override it to read
        the body in parts."""
        return io.BytesIO(self.get(path, params, headers, **kwargs))

    @abstractmethod
    def put(
        self,
        path: str,
        body: Union[bytes, str, None] = None,
        mimetype: str = "application/octet-stream",
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> bytes:
        """Make a PUT request to the given path with optional parameters and headers"""

    @abstractmethod
    def post(
        self,
        path: str,
        body: Union[bytes, str, None] = None,
        mimetype: str = "application/octet-stream",
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> bytes:
        """Make a POST request to the given path with optional parameters and headers"""

    @abstractmethod
    def upload(
        self,
        path: str,
        files: List[File],
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> bytes:
        """Upload a batch of files to the specified endpoint using a multipart POST request"""

    @abstractmethod
    def delete(
        self,
        path: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> bytes:
        """Make a DELETE request to the given path with optional parameters and headers"""

    @abstractmethod
    def connect(
        self,
        path: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> ClientConnection:
        """Begin a websocket connection to the given endpoint"""
