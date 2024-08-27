# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .DataStateId import DataStateId
from typing import Optional
np = import_numpy()

class DeprecatedDataStateJoin(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = DeprecatedDataStateJoin()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsDeprecatedDataStateJoin(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # DeprecatedDataStateJoin
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # DeprecatedDataStateJoin
    def From_(self) -> Optional[DataStateId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = DataStateId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # DeprecatedDataStateJoin
    def To(self) -> Optional[DataStateId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = DataStateId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # DeprecatedDataStateJoin
    def Operation(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # DeprecatedDataStateJoin
    def Distance(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Float32Flags, o + self._tab.Pos)
        return 0.0

def DeprecatedDataStateJoinStart(builder: flatbuffers.Builder):
    builder.StartObject(4)

def Start(builder: flatbuffers.Builder):
    DeprecatedDataStateJoinStart(builder)

def DeprecatedDataStateJoinAddFrom_(builder: flatbuffers.Builder, from_: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(from_), 0)

def AddFrom_(builder: flatbuffers.Builder, from_: int):
    DeprecatedDataStateJoinAddFrom_(builder, from_)

def DeprecatedDataStateJoinAddTo(builder: flatbuffers.Builder, to: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(to), 0)

def AddTo(builder: flatbuffers.Builder, to: int):
    DeprecatedDataStateJoinAddTo(builder, to)

def DeprecatedDataStateJoinAddOperation(builder: flatbuffers.Builder, operation: int):
    builder.PrependUint32Slot(2, operation, 0)

def AddOperation(builder: flatbuffers.Builder, operation: int):
    DeprecatedDataStateJoinAddOperation(builder, operation)

def DeprecatedDataStateJoinAddDistance(builder: flatbuffers.Builder, distance: float):
    builder.PrependFloat32Slot(3, distance, 0.0)

def AddDistance(builder: flatbuffers.Builder, distance: float):
    DeprecatedDataStateJoinAddDistance(builder, distance)

def DeprecatedDataStateJoinEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return DeprecatedDataStateJoinEnd(builder)