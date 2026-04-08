# Copyright (c), CommunityLogiq Software

import uuid
from abc import ABC, abstractmethod
from typing import Dict, List, NamedTuple, Optional, Union
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

    return f"{base}{api}"


class File(NamedTuple):
    name: str
    mimetype: str
    data: bytes


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
