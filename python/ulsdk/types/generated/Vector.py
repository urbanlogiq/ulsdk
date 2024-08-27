# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .NullableUint import NullableUint
from .ObjectId import ObjectId
from typing import Optional
np = import_numpy()

class Vector(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Vector()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsVector(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Vector
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Vector
    def Query(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Vector
    def Limit(self) -> Optional[NullableUint]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = NullableUint()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # List of vectordbs to query. If this is empty, query all available vectordbs.
    # Vector
    def Ids(self, j: int) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Vector
    def IdsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Vector
    def IdsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        return o == 0

    # Optionally limit the results to those with a distance value less than
    # max_distance. We treat max_distance=0 as no limit.
    # Vector
    def MaxDistance(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Float32Flags, o + self._tab.Pos)
        return 0.0

def VectorStart(builder: flatbuffers.Builder):
    builder.StartObject(4)

def Start(builder: flatbuffers.Builder):
    VectorStart(builder)

def VectorAddQuery(builder: flatbuffers.Builder, query: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(query), 0)

def AddQuery(builder: flatbuffers.Builder, query: int):
    VectorAddQuery(builder, query)

def VectorAddLimit(builder: flatbuffers.Builder, limit: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(limit), 0)

def AddLimit(builder: flatbuffers.Builder, limit: int):
    VectorAddLimit(builder, limit)

def VectorAddIds(builder: flatbuffers.Builder, ids: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(ids), 0)

def AddIds(builder: flatbuffers.Builder, ids: int):
    VectorAddIds(builder, ids)

def VectorStartIdsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartIdsVector(builder, numElems: int) -> int:
    return VectorStartIdsVector(builder, numElems)

def VectorAddMaxDistance(builder: flatbuffers.Builder, maxDistance: float):
    builder.PrependFloat32Slot(3, maxDistance, 0.0)

def AddMaxDistance(builder: flatbuffers.Builder, maxDistance: float):
    VectorAddMaxDistance(builder, maxDistance)

def VectorEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return VectorEnd(builder)