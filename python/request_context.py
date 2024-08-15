# Copyright (c), CommunityLogiq Software

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Union, NamedTuple

from .keys import Region, Environment


def _get_endpoint(region: Region, environment: Environment, api: str) -> str:
    base = None
    match (region, environment):
        case (Region.CA, Environment.Prod):
            base = "https://api.urbanlogiq.ca"
        case (Region.CA, Environment.Stage):
            base = "https://stage.urbanlogiq.ca"
        case (Region.US, Environment.Prod):
            base = "https://api.urbanlogiq.us"
        case (Region.US, Environment.Stage):
            base = "https://stage.urbanlogiq.us"

    return f"{base}{api}"


class File(NamedTuple):
    _name: str
    _mimetype: str
    _data: bytes


# A RequestContext is a superclass that enables code to use either signed
# requests-with-api-keys, bearer tokens, or other authentication schemes.
class RequestContext(ABC):
    def region(self):
        """Return the region of the context, if available"""
        raise NotImplementedError

    def env(self):
        """Return the environment of the context, if available"""
        raise NotImplementedError

    @abstractmethod
    def get(
        self,
        path: str,
        params: Optional[Dict] = None,
        headers: Dict[str, str] = dict(),
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
        headers: Dict[str, str] = dict(),
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
        headers: Dict[str, str] = dict(),
        **kwargs,
    ) -> bytes:
        """Make a POST request to the given path with optional parameters and headers"""

    @abstractmethod
    def upload(
        self,
        path: str,
        files: List[File],
    ):
        """Upload a batch of files to the specified endpoint using a multipart POST request"""

    @abstractmethod
    def delete(
        self,
        path: str,
        params: Optional[Dict] = None,
        headers: Dict[str, str] = dict(),
        **kwargs,
    ):
        """Make a DELETE request to the given path with optional parameters and headers"""
