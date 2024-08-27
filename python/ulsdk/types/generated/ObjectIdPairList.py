# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .ObjectIdPair import ObjectIdPair
from typing import Optional
np = import_numpy()

class ObjectIdPairList(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = ObjectIdPairList()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsObjectIdPairList(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # ObjectIdPairList
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # ObjectIdPairList
    def Pairs(self, j: int) -> Optional[ObjectIdPair]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = ObjectIdPair()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # ObjectIdPairList
    def PairsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # ObjectIdPairList
    def PairsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        return o == 0

def ObjectIdPairListStart(builder: flatbuffers.Builder):
    builder.StartObject(1)

def Start(builder: flatbuffers.Builder):
    ObjectIdPairListStart(builder)

def ObjectIdPairListAddPairs(builder: flatbuffers.Builder, pairs: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(pairs), 0)

def AddPairs(builder: flatbuffers.Builder, pairs: int):
    ObjectIdPairListAddPairs(builder, pairs)

def ObjectIdPairListStartPairsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartPairsVector(builder, numElems: int) -> int:
    return ObjectIdPairListStartPairsVector(builder, numElems)

def ObjectIdPairListEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return ObjectIdPairListEnd(builder)