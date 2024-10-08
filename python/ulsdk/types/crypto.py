# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from dataclasses import dataclass
from enum import Enum
from flatbuffers.table import Table
from flatbuffers.builder import Builder
from flatbuffers.util import RemoveSizePrefix
from typing import Union, List, Optional, Self, Tuple
from .generated.CryptHeader import CryptHeader as FbsCryptHeader
from .generated.EncryptedObject import EncryptedObject as FbsEncryptedObject
from .generated.Sha256 import Sha256 as FbsSha256
from .generated.Signature import Signature as FbsSignature
from .generated.Digest import Digest as FbsDigest


@dataclass
class Sha256:
    b: "List[int]"

    @classmethod
    def from_fbs(cls, o: FbsSha256) -> Self:
        b = list()
        if not o.BIsNone():
            for i in range(o.BLength()):
                b.append(o.B(i))
        return cls(b)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsSha256.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Sha256 import (
            Start,
            AddB,
            StartBVector,
            End,
        )
        StartBVector(builder, len(self.b))
        for i in reversed(range(len(self.b))):
            builder.PrependUint8(self.b[i])
        b_offset = builder.EndVector()
        
        Start(builder)
        AddB(builder, b_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        b = []
        return cls(b)

    def __eq__(self, other) -> bool:
        eq = True
        if len(self.b) != len(other.b):
            return False
        for i in range(len(self.b)):
            eq = eq and self.b[i] == other.b[i]

        return eq

@dataclass
class Digest:
    value: "Sha256"

    def serialize_to(self, builder: Builder) -> Tuple[int, int]:
        from .generated.Digest import Digest
        offset = self.value.serialize_to(builder)
        if isinstance(self.value, Sha256):
            return (offset, Digest().Sha256)
        raise ValueError("Invalid union type")

    @classmethod
    def from_fbs(cls, o: Optional[Table], ty: int) -> Self:
        assert o is not None
        source = o.Bytes
        pos = o.Pos
        Digest_ty_instance = FbsDigest()
        if ty == Digest_ty_instance.Sha256:
            val = FbsSha256();
            val.Init(source, pos)
            return cls(Sha256.from_fbs(val))
        else:
            raise ValueError("Invalid union type")

    @classmethod
    def make_default(cls) -> Self:
        return cls(Sha256.make_default())

    def __eq__(self, other) -> bool:
        if type(self.value) is not type(other.value):
            return False
        return self.value == other.value

@dataclass
class CryptHeader:
    # An ID for the key used to encrypt this particular encrypted object.
    kid: "str"

    nonce: "List[int]"

    plaintext_len: "int"

    @classmethod
    def from_fbs(cls, o: FbsCryptHeader) -> Self:
        kid_str = o.Kid()
        assert kid_str is not None
        kid = kid_str.decode('utf-8')
        nonce = list()
        if not o.NonceIsNone():
            for i in range(o.NonceLength()):
                nonce.append(o.Nonce(i))
        plaintext_len = o.PlaintextLen()
        return cls(kid, nonce, plaintext_len)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsCryptHeader.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.CryptHeader import (
            Start,
            AddKid,
            AddNonce,
            StartNonceVector,
            AddPlaintextLen,
            End,
        )
        kid_offset = builder.CreateString(self.kid)
        StartNonceVector(builder, len(self.nonce))
        for i in reversed(range(len(self.nonce))):
            builder.PrependUint8(self.nonce[i])
        nonce_offset = builder.EndVector()
        
        Start(builder)
        AddKid(builder, kid_offset)
        AddNonce(builder, nonce_offset)
        AddPlaintextLen(builder, self.plaintext_len)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        kid = ""
        nonce = []
        plaintext_len = 0
        return cls(kid, nonce, plaintext_len)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.kid == other.kid
        if len(self.nonce) != len(other.nonce):
            return False
        for i in range(len(self.nonce)):
            eq = eq and self.nonce[i] == other.nonce[i]
        eq = eq and self.plaintext_len == other.plaintext_len

        return eq

@dataclass
class EncryptedObject:
    header: "CryptHeader"

    obj: "List[int]"

    @classmethod
    def from_fbs(cls, o: FbsEncryptedObject) -> Self:
        header_obj = o.Header()
        if header_obj is not None:
            header = CryptHeader.from_fbs(header_obj)
        else:
            raise ValueError("Header is required")
        obj = list()
        if not o.ObjIsNone():
            for i in range(o.ObjLength()):
                obj.append(o.Obj(i))
        return cls(header, obj)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsEncryptedObject.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.EncryptedObject import (
            Start,
            AddHeader,
            AddObj,
            StartObjVector,
            End,
        )
        header_offset = self.header.serialize_to(builder)
        StartObjVector(builder, len(self.obj))
        for i in reversed(range(len(self.obj))):
            builder.PrependUint8(self.obj[i])
        obj_offset = builder.EndVector()
        
        Start(builder)
        AddHeader(builder, header_offset)
        AddObj(builder, obj_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        header = CryptHeader.make_default()
        obj = []
        return cls(header, obj)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.header == other.header
        if len(self.obj) != len(other.obj):
            return False
        for i in range(len(self.obj)):
            eq = eq and self.obj[i] == other.obj[i]

        return eq

@dataclass
class Signature:
    kid: "str"

    sig: "List[int]"

    @classmethod
    def from_fbs(cls, o: FbsSignature) -> Self:
        kid_str = o.Kid()
        assert kid_str is not None
        kid = kid_str.decode('utf-8')
        sig = list()
        if not o.SigIsNone():
            for i in range(o.SigLength()):
                sig.append(o.Sig(i))
        return cls(kid, sig)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsSignature.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Signature import (
            Start,
            AddKid,
            AddSig,
            StartSigVector,
            End,
        )
        kid_offset = builder.CreateString(self.kid)
        StartSigVector(builder, len(self.sig))
        for i in reversed(range(len(self.sig))):
            builder.PrependUint8(self.sig[i])
        sig_offset = builder.EndVector()
        
        Start(builder)
        AddKid(builder, kid_offset)
        AddSig(builder, sig_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        kid = ""
        sig = []
        return cls(kid, sig)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.kid == other.kid
        if len(self.sig) != len(other.sig):
            return False
        for i in range(len(self.sig)):
            eq = eq and self.sig[i] == other.sig[i]

        return eq
