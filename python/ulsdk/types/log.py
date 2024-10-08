# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from dataclasses import dataclass
from enum import Enum
from flatbuffers.table import Table
from flatbuffers.builder import Builder
from flatbuffers.util import RemoveSizePrefix
from typing import Union, List, Optional, Self, Tuple
from .value import (
    Point2D,
    Tri2D,
    VArray,
    VBool,
    VBytes,
    VChar,
    VF32,
    VF64,
    VFixedSizeBytes,
    VI16,
    VI32,
    VI64,
    VI8,
    VIsize,
    VNull,
    VStr,
    VTimestampMs,
    VTimestampMsUtc,
    VTimestampNs,
    VTimestampNsUtc,
    VTri2D,
    VU16,
    VU32,
    VU64,
    VU8,
    VUnit,
    VUsize,
    Value,
    ValueInstance,
    ValueTy,
)
from .generated.Label import Label as FbsLabel
from .generated.Log import Log as FbsLog
from .generated.Pair import Pair as FbsPair
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

class Severity(Enum):
    CRITICAL = 0
    ERROR = 1
    WARN = 2
    INFO = 3
    DEBUG = 4
    TRACE = 5


@dataclass
class Label:
    key: "str"

    value: "str"

    @classmethod
    def from_fbs(cls, o: FbsLabel) -> Self:
        key_str = o.Key()
        assert key_str is not None
        key = key_str.decode('utf-8')
        value_str = o.Value()
        assert value_str is not None
        value = value_str.decode('utf-8')
        return cls(key, value)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsLabel.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Label import (
            Start,
            AddKey,
            AddValue,
            End,
        )
        key_offset = builder.CreateString(self.key)
        value_offset = builder.CreateString(self.value)
        
        Start(builder)
        AddKey(builder, key_offset)
        AddValue(builder, value_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        key = ""
        value = ""
        return cls(key, value)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.key == other.key
        eq = eq and self.value == other.value

        return eq

@dataclass
class Log:
    labels: "List[Label]"

    pairs: "List[Pair]"

    timestamp: "int"

    @classmethod
    def from_fbs(cls, o: FbsLog) -> Self:
        labels = list()
        if not o.LabelsIsNone():
            for i in range(o.LabelsLength()):
                labels_val = None
                labels_obj = o.Labels(i)
                if labels_obj is not None:
                    labels_val = Label.from_fbs(labels_obj)
                labels.append(labels_val)
        pairs = list()
        if not o.PairsIsNone():
            for i in range(o.PairsLength()):
                pairs_val = None
                pairs_obj = o.Pairs(i)
                if pairs_obj is not None:
                    pairs_val = Pair.from_fbs(pairs_obj)
                pairs.append(pairs_val)
        timestamp = o.Timestamp()
        return cls(labels, pairs, timestamp)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsLog.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Log import (
            Start,
            AddLabels,
            StartLabelsVector,
            AddPairs,
            StartPairsVector,
            AddTimestamp,
            End,
        )
        labels_offsets = list()
        for value in self.labels:
            labels_offsets.append(value.serialize_to(builder))
        StartLabelsVector(builder, len(self.labels))
        for i in reversed(range(len(self.labels))):
            builder.PrependUOffsetTRelative(labels_offsets[i])
        labels_offset = builder.EndVector()
        pairs_offsets = list()
        for value in self.pairs:
            pairs_offsets.append(value.serialize_to(builder))
        StartPairsVector(builder, len(self.pairs))
        for i in reversed(range(len(self.pairs))):
            builder.PrependUOffsetTRelative(pairs_offsets[i])
        pairs_offset = builder.EndVector()
        
        Start(builder)
        AddLabels(builder, labels_offset)
        AddPairs(builder, pairs_offset)
        AddTimestamp(builder, self.timestamp)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        labels = []
        pairs = []
        timestamp = 0
        return cls(labels, pairs, timestamp)

    def __eq__(self, other) -> bool:
        eq = True
        if len(self.labels) != len(other.labels):
            return False
        for i in range(len(self.labels)):
            eq = eq and self.labels[i] == other.labels[i]
        if len(self.pairs) != len(other.pairs):
            return False
        for i in range(len(self.pairs)):
            eq = eq and self.pairs[i] == other.pairs[i]
        eq = eq and self.timestamp == other.timestamp

        return eq

@dataclass
class Pair:
    key: "str"

    value: "Value"

    @classmethod
    def from_fbs(cls, o: FbsPair) -> Self:
        key_str = o.Key()
        assert key_str is not None
        key = key_str.decode('utf-8')
        value_val = o.Value()
        if value_val is not None:
            value_ty = o.ValueType()
            value = Value.from_fbs(value_val, value_ty)
        else:
            raise ValueError("Value is required")
        return cls(key, value)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsPair.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Pair import (
            Start,
            AddKey,
            AddValue,
            AddValueType,
            End,
        )
        key_offset = builder.CreateString(self.key)
        value_offset, value_ty = self.value.serialize_to(builder)
        
        Start(builder)
        AddKey(builder, key_offset)
        AddValue(builder, value_offset)
        AddValueType(builder, value_ty)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        key = ""
        value = Value.make_default()
        return cls(key, value)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.key == other.key
        eq = eq and self.value == other.value

        return eq
