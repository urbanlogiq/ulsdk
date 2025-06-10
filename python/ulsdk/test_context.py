# Copyright (c), CommunityLogiq Software

import uuid
from typing import Dict, List, Optional, Union

from .keys import Environment, Region
from .request_context import RequestContext, File
from .api_key_context import ApiKeyContext

class TestContext(RequestContext):
    def __init__(
        self,
        context: ApiKeyContext
    ):
        self._context = context
        self._response = bytes()

    def user_id(self) -> uuid.UUID:
        return self._context.user_id()

    def env(self) -> Environment:
        return self._context.env()

    def region(self) -> Region:
        return self._context.region()

    def get(
        self,
        path: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> bytes:
        echo_path = "/v1/echo/"
        self._context.get(echo_path, params, headers, **kwargs)
        return self.response

    def put(
        self,
        path: str,
        body: Union[bytes, str, None] = None,
        mimetype: str = "application/octet-stream",
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> bytes:
        echo_path = "/v1/echo/"
        response = self._context.put(echo_path, body, mimetype, params, headers, **kwargs)
        if response != self.response:
            raise Exception("Test failure, expected response to match request")
        return self.response

    def post(
        self,
        path: str,
        body: Union[bytes, str, None] = None,
        mimetype: str = "application/octet-stream",
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> bytes:
        echo_path = "/v1/echo/"
        response = self._context.post(echo_path, body, mimetype, params, headers, **kwargs)
        if response != self.response:
            raise Exception("Test failure, expected response to match request")
        return self.response

    def upload(
        self,
        path: str,
        files: List[File],
    ) -> bytes:
        echo_path = "/v1/echo/"
        self._context.upload(echo_path, files)
        return self.response

    def delete(
        self,
        path: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> bytes:
        echo_path = "/v1/echo/"
        self._context.delete(echo_path, params, headers, **kwargs)
        return self.response
