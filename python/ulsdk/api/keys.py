# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from dataclasses import dataclass
import json
from pyarrow import RecordBatch, BufferOutputStream, RecordBatchStreamWriter, RecordBatchStreamReader
from typing import Optional, Any, List, Dict, Self
from urllib.parse import quote_plus
from uuid import UUID
from ..request_context import RequestContext

@dataclass
class Key:
    id_: "str"
    pubkey: "Optional[str]"
    created: "int"
    last: "Optional[int]"
    expiry: "Optional[int]"
    comment: "Optional[str]"

    def to_dict(self) -> Dict[str, Any]:
        o = dict()
        o["id"] = self.id_
        o["pubkey"] = None
        if self.pubkey is not None:
            o["pubkey"] = self.pubkey
        o["created"] = self.created
        o["last"] = None
        if self.last is not None:
            o["last"] = self.last
        o["expiry"] = None
        if self.expiry is not None:
            o["expiry"] = self.expiry
        o["comment"] = None
        if self.comment is not None:
            o["comment"] = self.comment
        return o

    @classmethod
    def from_dict(cls, o: Dict[str, Any]) -> Self:
        id_ = None
        pubkey = None
        created = None
        last = None
        expiry = None
        comment = None
    
        for key in o:
            if key == "id":
                id__var = o[key]
                assert type(id__var) is str
                id_ = id__var
            elif key == "pubkey":
                if o[key] is not None:
                    pubkey_var = o[key]
                    assert type(pubkey_var) is str
                    pubkey = pubkey_var
                else:
                    pubkey = None
            elif key == "created":
                created_var = o[key]
                assert type(created_var) is int
                created = created_var
            elif key == "last":
                if o[key] is not None:
                    last_var = o[key]
                    assert type(last_var) is int
                    last = last_var
                else:
                    last = None
            elif key == "expiry":
                if o[key] is not None:
                    expiry_var = o[key]
                    assert type(expiry_var) is int
                    expiry = expiry_var
                else:
                    expiry = None
            elif key == "comment":
                if o[key] is not None:
                    comment_var = o[key]
                    assert type(comment_var) is str
                    comment = comment_var
                else:
                    comment = None
    
        assert id_ is not None
        assert created is not None
    
        return cls(id_, pubkey, created, last, expiry, comment)

    @classmethod
    def make_default(cls) -> Self:
        id = ""
        pubkey = None
        created = 0
        last = None
        expiry = None
        comment = None
    
        return cls(id, pubkey, created, last, expiry, comment)

@dataclass
class GetKeys:
    keys: "List[Key]"

    def to_dict(self) -> Dict[str, Any]:
        o = dict()
        keys_list = []
        for item in self.keys:
            keys_var = item.to_dict()
            keys_list.append(keys_var)
        o["keys"] = keys_list
        return o

    @classmethod
    def from_dict(cls, o: Dict[str, Any]) -> Self:
        keys = None
    
        for key in o:
            if key == "keys":
                keys_var = o[key]
                assert type(keys_var) is list
                keys = []
                for item in keys_var:
                    keys_item_var = item
                    assert type(keys_item_var) is dict
                    keys_item = Key.from_dict(keys_item_var)
                    keys.append(keys_item)
    
        assert keys is not None
    
        return cls(keys)

    @classmethod
    def make_default(cls) -> Self:
        keys = []
    
        return cls(keys)

@dataclass
class CreateKey:
    id_: "str"
    secret_key: "str"

    def to_dict(self) -> Dict[str, Any]:
        o = dict()
        o["id"] = self.id_
        o["secret_key"] = self.secret_key
        return o

    @classmethod
    def from_dict(cls, o: Dict[str, Any]) -> Self:
        id_ = None
        secret_key = None
    
        for key in o:
            if key == "id":
                id__var = o[key]
                assert type(id__var) is str
                id_ = id__var
            elif key == "secretKey":
                secret_key_var = o[key]
                assert type(secret_key_var) is str
                secret_key = secret_key_var
    
        assert id_ is not None
        assert secret_key is not None
    
        return cls(id_, secret_key)

    @classmethod
    def make_default(cls) -> Self:
        id = ""
        secretKey = ""
    
        return cls(id, secretKey)

@dataclass
class UpdateKey:
    comment: "Optional[str]"
    expiry: "Optional[int]"

    def to_dict(self) -> Dict[str, Any]:
        o = dict()
        o["comment"] = None
        if self.comment is not None:
            o["comment"] = self.comment
        o["expiry"] = None
        if self.expiry is not None:
            o["expiry"] = self.expiry
        return o

    @classmethod
    def from_dict(cls, o: Dict[str, Any]) -> Self:
        comment = None
        expiry = None
    
        for key in o:
            if key == "comment":
                if o[key] is not None:
                    comment_var = o[key]
                    assert type(comment_var) is str
                    comment = comment_var
                else:
                    comment = None
            elif key == "expiry":
                if o[key] is not None:
                    expiry_var = o[key]
                    assert type(expiry_var) is int
                    expiry = expiry_var
                else:
                    expiry = None
    
    
        return cls(comment, expiry)

    @classmethod
    def make_default(cls) -> Self:
        comment = None
        expiry = None
    
        return cls(comment, expiry)

def get_keys(
    ctx: RequestContext,
) -> GetKeys:
    """Retrieves a listing of the API keys associated with the current user.

    Arguments:
    ctx: RequestContext -- A request context object

    Returns:
    A list of all the API keys currently associated with the current user
    """

    path = "/v1/api/uldirectory/v1/keys/"
    params = dict()
    headers = dict()
    res = ctx.get(path, params=params, headers=headers)
    res_dict = json.loads(res)
    return GetKeys.from_dict(res_dict)

def create_key(
    ctx: RequestContext,
) -> CreateKey:
    """Creates a new API key for the current user.

    Arguments:
    ctx: RequestContext -- A request context object

    Returns:
    The details of the created key, including the secret key. This secret key cannot be retrieved again, if it is lost a new key must be created.
    """

    path = "/v1/api/uldirectory/v1/keys/"
    params = dict()
    headers = dict()
    body = None
    res = ctx.post(path, body=body, mimetype="text/plain", params=params, headers=headers)
    res_dict = json.loads(res)
    return CreateKey.from_dict(res_dict)

def update_key(
    ctx: RequestContext,
    id_: UUID,
    update_key: UpdateKey,
) -> None:
    """Updates an API key by id.

    Arguments:
    ctx: RequestContext -- A request context object
    id_: UUID -- The ID of the key to update.
    update_key: UpdateKey -- The details with which to update the key.
    """

    path = "/v1/api/uldirectory/v1/keys/:id"
    path.replace(":id", str(id_), 1)

    params = dict()
    headers = dict()
    body = json.dumps(update_key.to_dict())
    ctx.put(path, body=body, mimetype="application/json", params=params, headers=headers)
    return

def get_key(
    ctx: RequestContext,
    id_: UUID,
) -> Key:
    """Retrieves an API key by id.

    Arguments:
    ctx: RequestContext -- A request context object
    id_: UUID -- The ID of the key to retrieve.

    Returns:
    The key details. Note that the secret key is not stored and cannot be retrieved with this API.
    """

    path = "/v1/api/uldirectory/v1/keys/:id"
    path.replace(":id", str(id_), 1)

    params = dict()
    headers = dict()
    res = ctx.get(path, params=params, headers=headers)
    res_dict = json.loads(res)
    return Key.from_dict(res_dict)

def delete_key(
    ctx: RequestContext,
    id_: UUID,
) -> None:
    """Deletes an API key by id.

    Arguments:
    ctx: RequestContext -- A request context object
    id_: UUID -- The ID of the key to delete
    """

    path = "/v1/api/uldirectory/v1/keys/:id"
    path.replace(":id", str(id_), 1)

    params = dict()
    headers = dict()
    ctx.delete(path, params=params, headers=headers)
    return