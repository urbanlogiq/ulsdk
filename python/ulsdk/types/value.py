# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from dataclasses import dataclass
from enum import Enum
from flatbuffers.table import Table
from flatbuffers.builder import Builder
from flatbuffers.util import RemoveSizePrefix
from typing import Union, List, Optional, Self, Tuple
from .generated.Point2D import Point2D as FbsPoint2D
from .generated.Tri2D import Tri2D as FbsTri2D
from .generated.VArray import VArray as FbsVArray
from .generated.VBool import VBool as FbsVBool
from .generated.VBytes import VBytes as FbsVBytes
from .generated.VChar import VChar as FbsVChar
from .generated.VF32 import VF32 as FbsVF32
from .generated.VF64 import VF64 as FbsVF64
from .generated.VFixedSizeBytes import VFixedSizeBytes as FbsVFixedSizeBytes
from .generated.VI16 import VI16 as FbsVI16
from .generated.VI32 import VI32 as FbsVI32
from .generated.VI64 import VI64 as FbsVI64
from .generated.VI8 import VI8 as FbsVI8
from .generated.VIsize import VIsize as FbsVIsize
from .generated.VNull import VNull as FbsVNull
from .generated.VStr import VStr as FbsVStr
from .generated.VTimestampMs import VTimestampMs as FbsVTimestampMs
from .generated.VTimestampMsUtc import VTimestampMsUtc as FbsVTimestampMsUtc
from .generated.VTimestampNs import VTimestampNs as FbsVTimestampNs
from .generated.VTimestampNsUtc import VTimestampNsUtc as FbsVTimestampNsUtc
from .generated.VTri2D import VTri2D as FbsVTri2D
from .generated.VU16 import VU16 as FbsVU16
from .generated.VU32 import VU32 as FbsVU32
from .generated.VU64 import VU64 as FbsVU64
from .generated.VU8 import VU8 as FbsVU8
from .generated.VUnit import VUnit as FbsVUnit
from .generated.VUsize import VUsize as FbsVUsize
from .generated.ValueInstance import ValueInstance as FbsValueInstance
from .generated.Value import Value as FbsValue

class ValueTy(Enum):
    Bool = 0
    Unit = 1
    Char = 2
    Null = 3
    I8 = 4
    U8 = 5
    I16 = 6
    U16 = 7
    I32 = 8
    U32 = 9
    F32 = 10
    Isize = 11
    Usize = 12
    I64 = 13
    U64 = 14
    F64 = 15
    Str = 16
    Bytes = 17
    Array = 18
    Tri2D = 19
    FixedSizeBytes = 20
    TimestampMsUtc = 21
    TimestampMs = 22
    TimestampNsUtc = 23
    TimestampNs = 24


@dataclass
class VBool:
    v: "bool"

    @classmethod
    def from_fbs(cls, o: FbsVBool) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVBool.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VBool import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = False
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VUnit:
    @classmethod
    def from_fbs(cls, o: FbsVUnit) -> Self:
        return cls()

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVUnit.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VUnit import (
            Start,
            End,
        )
        
        Start(builder)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        return cls()

    def __eq__(self, other) -> bool:
        eq = True

        return eq

@dataclass
class VChar:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVChar) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVChar.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VChar import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VNull:
    @classmethod
    def from_fbs(cls, o: FbsVNull) -> Self:
        return cls()

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVNull.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VNull import (
            Start,
            End,
        )
        
        Start(builder)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        return cls()

    def __eq__(self, other) -> bool:
        eq = True

        return eq

@dataclass
class VI8:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVI8) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVI8.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VI8 import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VU8:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVU8) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVU8.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VU8 import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VI16:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVI16) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVI16.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VI16 import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VU16:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVU16) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVU16.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VU16 import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VI32:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVI32) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVI32.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VI32 import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VU32:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVU32) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVU32.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VU32 import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VF32:
    v: "float"

    @classmethod
    def from_fbs(cls, o: FbsVF32) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVF32.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VF32 import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0.0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VIsize:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVIsize) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVIsize.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VIsize import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VUsize:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVUsize) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVUsize.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VUsize import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VI64:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVI64) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVI64.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VI64 import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VU64:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVU64) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVU64.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VU64 import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VF64:
    v: "float"

    @classmethod
    def from_fbs(cls, o: FbsVF64) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVF64.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VF64 import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0.0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VStr:
    v: "str"

    @classmethod
    def from_fbs(cls, o: FbsVStr) -> Self:
        v_str = o.V()
        assert v_str is not None
        v = v_str.decode('utf-8')
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVStr.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VStr import (
            Start,
            AddV,
            End,
        )
        v_offset = builder.CreateString(self.v)
        
        Start(builder)
        AddV(builder, v_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = ""
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VBytes:
    v: "List[int]"

    @classmethod
    def from_fbs(cls, o: FbsVBytes) -> Self:
        v = list()
        if not o.VIsNone():
            for i in range(o.VLength()):
                v.append(o.V(i))
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVBytes.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VBytes import (
            Start,
            AddV,
            StartVVector,
            End,
        )
        StartVVector(builder, len(self.v))
        for i in reversed(range(len(self.v))):
            builder.PrependUint8(self.v[i])
        v_offset = builder.EndVector()
        
        Start(builder)
        AddV(builder, v_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = []
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        if len(self.v) != len(other.v):
            return False
        for i in range(len(self.v)):
            eq = eq and self.v[i] == other.v[i]

        return eq

@dataclass
class VArray:
    v: "List[ValueInstance]"

    @classmethod
    def from_fbs(cls, o: FbsVArray) -> Self:
        v = list()
        if not o.VIsNone():
            for i in range(o.VLength()):
                v_val = None
                v_obj = o.V(i)
                if v_obj is not None:
                    v_val = ValueInstance.from_fbs(v_obj)
                v.append(v_val)
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVArray.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VArray import (
            Start,
            AddV,
            StartVVector,
            End,
        )
        v_offsets = list()
        for value in self.v:
            v_offsets.append(value.serialize_to(builder))
        StartVVector(builder, len(self.v))
        for i in reversed(range(len(self.v))):
            builder.PrependUOffsetTRelative(v_offsets[i])
        v_offset = builder.EndVector()
        
        Start(builder)
        AddV(builder, v_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = []
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        if len(self.v) != len(other.v):
            return False
        for i in range(len(self.v)):
            eq = eq and self.v[i] == other.v[i]

        return eq

@dataclass
class Point2D:
    x: "float"

    y: "float"

    @classmethod
    def from_fbs(cls, o: FbsPoint2D) -> Self:
        x = o.X()
        y = o.Y()
        return cls(x, y)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Point2D import CreatePoint2D
        x = self.x
        y = self.y
        return CreatePoint2D(builder, x, y)

    @classmethod
    def make_default(cls) -> Self:
        x = 0.0
        y = 0.0
        return cls(x, y)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.x == other.x
        eq = eq and self.y == other.y

        return eq

@dataclass
class Tri2D:
    p0: Optional["Point2D"]

    p1: Optional["Point2D"]

    p2: Optional["Point2D"]

    @classmethod
    def from_fbs(cls, o: FbsTri2D) -> Self:
        p0_obj = o.P0(FbsPoint2D())
        p0 = Point2D.from_fbs(p0_obj)
        p1_obj = o.P1(FbsPoint2D())
        p1 = Point2D.from_fbs(p1_obj)
        p2_obj = o.P2(FbsPoint2D())
        p2 = Point2D.from_fbs(p2_obj)
        return cls(p0, p1, p2)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Tri2D import CreateTri2D
        p0_obj = self.p0
        assert p0_obj is not None
        p0_x = p0_obj.x
        p0_y = p0_obj.y
        p1_obj = self.p1
        assert p1_obj is not None
        p1_x = p1_obj.x
        p1_y = p1_obj.y
        p2_obj = self.p2
        assert p2_obj is not None
        p2_x = p2_obj.x
        p2_y = p2_obj.y
        return CreateTri2D(builder, p0_x, p0_y, p1_x, p1_y, p2_x, p2_y)

    @classmethod
    def make_default(cls) -> Self:
        p0 = Point2D.make_default()
        p1 = Point2D.make_default()
        p2 = Point2D.make_default()
        return cls(p0, p1, p2)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.p0 == other.p0
        eq = eq and self.p1 == other.p1
        eq = eq and self.p2 == other.p2

        return eq

@dataclass
class VTri2D:
    v: "Tri2D"

    @classmethod
    def from_fbs(cls, o: FbsVTri2D) -> Self:
        v_obj = o.V()
        if v_obj is not None:
            v = Tri2D.from_fbs(v_obj)
        else:
            raise ValueError("V is required")
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVTri2D.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VTri2D import (
            Start,
            AddV,
            End,
        )
        v_offset = self.v.serialize_to(builder)
        
        Start(builder)
        AddV(builder, v_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = Tri2D.make_default()
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VFixedSizeBytes:
    sz: "int"

    v: "List[int]"

    @classmethod
    def from_fbs(cls, o: FbsVFixedSizeBytes) -> Self:
        sz = o.Sz()
        v = list()
        if not o.VIsNone():
            for i in range(o.VLength()):
                v.append(o.V(i))
        return cls(sz, v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVFixedSizeBytes.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VFixedSizeBytes import (
            Start,
            AddSz,
            AddV,
            StartVVector,
            End,
        )
        StartVVector(builder, len(self.v))
        for i in reversed(range(len(self.v))):
            builder.PrependUint8(self.v[i])
        v_offset = builder.EndVector()
        
        Start(builder)
        AddSz(builder, self.sz)
        AddV(builder, v_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        sz = 0
        v = []
        return cls(sz, v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.sz == other.sz
        if len(self.v) != len(other.v):
            return False
        for i in range(len(self.v)):
            eq = eq and self.v[i] == other.v[i]

        return eq

@dataclass
class VTimestampMsUtc:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVTimestampMsUtc) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVTimestampMsUtc.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VTimestampMsUtc import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VTimestampMs:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVTimestampMs) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVTimestampMs.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VTimestampMs import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VTimestampNsUtc:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVTimestampNsUtc) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVTimestampNsUtc.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VTimestampNsUtc import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class VTimestampNs:
    v: "int"

    @classmethod
    def from_fbs(cls, o: FbsVTimestampNs) -> Self:
        v = o.V()
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsVTimestampNs.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.VTimestampNs import (
            Start,
            AddV,
            End,
        )
        
        Start(builder)
        AddV(builder, self.v)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = 0
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq

@dataclass
class Value:
    value: Union[
        "VBool",
        "VUnit",
        "VChar",
        "VNull",
        "VI8",
        "VU8",
        "VI16",
        "VU16",
        "VI32",
        "VU32",
        "VF32",
        "VIsize",
        "VUsize",
        "VI64",
        "VU64",
        "VF64",
        "VStr",
        "VBytes",
        "VArray",
        "VTri2D",
        "VFixedSizeBytes",
        "VTimestampMsUtc",
        "VTimestampMs",
        "VTimestampNsUtc",
        "VTimestampNs",
    ]

    def serialize_to(self, builder: Builder) -> Tuple[int, int]:
        from .generated.Value import Value
        offset = self.value.serialize_to(builder)
        if isinstance(self.value, VBool):
            return (offset, Value().VBool)
        elif isinstance(self.value, VUnit):
            return (offset, Value().VUnit)
        elif isinstance(self.value, VChar):
            return (offset, Value().VChar)
        elif isinstance(self.value, VNull):
            return (offset, Value().VNull)
        elif isinstance(self.value, VI8):
            return (offset, Value().VI8)
        elif isinstance(self.value, VU8):
            return (offset, Value().VU8)
        elif isinstance(self.value, VI16):
            return (offset, Value().VI16)
        elif isinstance(self.value, VU16):
            return (offset, Value().VU16)
        elif isinstance(self.value, VI32):
            return (offset, Value().VI32)
        elif isinstance(self.value, VU32):
            return (offset, Value().VU32)
        elif isinstance(self.value, VF32):
            return (offset, Value().VF32)
        elif isinstance(self.value, VIsize):
            return (offset, Value().VIsize)
        elif isinstance(self.value, VUsize):
            return (offset, Value().VUsize)
        elif isinstance(self.value, VI64):
            return (offset, Value().VI64)
        elif isinstance(self.value, VU64):
            return (offset, Value().VU64)
        elif isinstance(self.value, VF64):
            return (offset, Value().VF64)
        elif isinstance(self.value, VStr):
            return (offset, Value().VStr)
        elif isinstance(self.value, VBytes):
            return (offset, Value().VBytes)
        elif isinstance(self.value, VArray):
            return (offset, Value().VArray)
        elif isinstance(self.value, VTri2D):
            return (offset, Value().VTri2D)
        elif isinstance(self.value, VFixedSizeBytes):
            return (offset, Value().VFixedSizeBytes)
        elif isinstance(self.value, VTimestampMsUtc):
            return (offset, Value().VTimestampMsUtc)
        elif isinstance(self.value, VTimestampMs):
            return (offset, Value().VTimestampMs)
        elif isinstance(self.value, VTimestampNsUtc):
            return (offset, Value().VTimestampNsUtc)
        elif isinstance(self.value, VTimestampNs):
            return (offset, Value().VTimestampNs)
        raise ValueError("Invalid union type")

    @classmethod
    def from_fbs(cls, o: Optional[Table], ty: int) -> Self:
        assert o is not None
        source = o.Bytes
        pos = o.Pos
        Value_ty_instance = FbsValue()
        if ty == Value_ty_instance.VBool:
            val = FbsVBool();
            val.Init(source, pos)
            return cls(VBool.from_fbs(val))
        elif ty == Value_ty_instance.VUnit:
            val = FbsVUnit();
            val.Init(source, pos)
            return cls(VUnit.from_fbs(val))
        elif ty == Value_ty_instance.VChar:
            val = FbsVChar();
            val.Init(source, pos)
            return cls(VChar.from_fbs(val))
        elif ty == Value_ty_instance.VNull:
            val = FbsVNull();
            val.Init(source, pos)
            return cls(VNull.from_fbs(val))
        elif ty == Value_ty_instance.VI8:
            val = FbsVI8();
            val.Init(source, pos)
            return cls(VI8.from_fbs(val))
        elif ty == Value_ty_instance.VU8:
            val = FbsVU8();
            val.Init(source, pos)
            return cls(VU8.from_fbs(val))
        elif ty == Value_ty_instance.VI16:
            val = FbsVI16();
            val.Init(source, pos)
            return cls(VI16.from_fbs(val))
        elif ty == Value_ty_instance.VU16:
            val = FbsVU16();
            val.Init(source, pos)
            return cls(VU16.from_fbs(val))
        elif ty == Value_ty_instance.VI32:
            val = FbsVI32();
            val.Init(source, pos)
            return cls(VI32.from_fbs(val))
        elif ty == Value_ty_instance.VU32:
            val = FbsVU32();
            val.Init(source, pos)
            return cls(VU32.from_fbs(val))
        elif ty == Value_ty_instance.VF32:
            val = FbsVF32();
            val.Init(source, pos)
            return cls(VF32.from_fbs(val))
        elif ty == Value_ty_instance.VIsize:
            val = FbsVIsize();
            val.Init(source, pos)
            return cls(VIsize.from_fbs(val))
        elif ty == Value_ty_instance.VUsize:
            val = FbsVUsize();
            val.Init(source, pos)
            return cls(VUsize.from_fbs(val))
        elif ty == Value_ty_instance.VI64:
            val = FbsVI64();
            val.Init(source, pos)
            return cls(VI64.from_fbs(val))
        elif ty == Value_ty_instance.VU64:
            val = FbsVU64();
            val.Init(source, pos)
            return cls(VU64.from_fbs(val))
        elif ty == Value_ty_instance.VF64:
            val = FbsVF64();
            val.Init(source, pos)
            return cls(VF64.from_fbs(val))
        elif ty == Value_ty_instance.VStr:
            val = FbsVStr();
            val.Init(source, pos)
            return cls(VStr.from_fbs(val))
        elif ty == Value_ty_instance.VBytes:
            val = FbsVBytes();
            val.Init(source, pos)
            return cls(VBytes.from_fbs(val))
        elif ty == Value_ty_instance.VArray:
            val = FbsVArray();
            val.Init(source, pos)
            return cls(VArray.from_fbs(val))
        elif ty == Value_ty_instance.VTri2D:
            val = FbsVTri2D();
            val.Init(source, pos)
            return cls(VTri2D.from_fbs(val))
        elif ty == Value_ty_instance.VFixedSizeBytes:
            val = FbsVFixedSizeBytes();
            val.Init(source, pos)
            return cls(VFixedSizeBytes.from_fbs(val))
        elif ty == Value_ty_instance.VTimestampMsUtc:
            val = FbsVTimestampMsUtc();
            val.Init(source, pos)
            return cls(VTimestampMsUtc.from_fbs(val))
        elif ty == Value_ty_instance.VTimestampMs:
            val = FbsVTimestampMs();
            val.Init(source, pos)
            return cls(VTimestampMs.from_fbs(val))
        elif ty == Value_ty_instance.VTimestampNsUtc:
            val = FbsVTimestampNsUtc();
            val.Init(source, pos)
            return cls(VTimestampNsUtc.from_fbs(val))
        elif ty == Value_ty_instance.VTimestampNs:
            val = FbsVTimestampNs();
            val.Init(source, pos)
            return cls(VTimestampNs.from_fbs(val))
        else:
            raise ValueError("Invalid union type")

    @classmethod
    def make_default(cls) -> Self:
        return cls(VBool.make_default())

    def __eq__(self, other) -> bool:
        if type(self.value) is not type(other.value):
            return False
        return self.value == other.value

@dataclass
class ValueInstance:
    v: "Value"

    @classmethod
    def from_fbs(cls, o: FbsValueInstance) -> Self:
        v_val = o.V()
        if v_val is not None:
            v_ty = o.VType()
            v = Value.from_fbs(v_val, v_ty)
        else:
            raise ValueError("V is required")
        return cls(v)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsValueInstance.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.ValueInstance import (
            Start,
            AddV,
            AddVType,
            End,
        )
        v_offset, v_ty = self.v.serialize_to(builder)
        
        Start(builder)
        AddV(builder, v_offset)
        AddVType(builder, v_ty)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        v = Value.make_default()
        return cls(v)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.v == other.v

        return eq
