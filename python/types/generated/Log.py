# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .Label import Label
from .Pair import Pair
from typing import Optional
np = import_numpy()

class Log(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Log()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsLog(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Log
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Log
    def Timestamp(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int64Flags, o + self._tab.Pos)
        return 0

    # Log
    def Labels(self, j: int) -> Optional[Label]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = Label()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Log
    def LabelsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Log
    def LabelsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        return o == 0

    # Log
    def Pairs(self, j: int) -> Optional[Pair]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = Pair()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Log
    def PairsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Log
    def PairsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        return o == 0

def LogStart(builder: flatbuffers.Builder):
    builder.StartObject(4)

def Start(builder: flatbuffers.Builder):
    LogStart(builder)

def LogAddTimestamp(builder: flatbuffers.Builder, timestamp: int):
    builder.PrependInt64Slot(0, timestamp, 0)

def AddTimestamp(builder: flatbuffers.Builder, timestamp: int):
    LogAddTimestamp(builder, timestamp)

def LogAddLabels(builder: flatbuffers.Builder, labels: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(labels), 0)

def AddLabels(builder: flatbuffers.Builder, labels: int):
    LogAddLabels(builder, labels)

def LogStartLabelsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartLabelsVector(builder, numElems: int) -> int:
    return LogStartLabelsVector(builder, numElems)

def LogAddPairs(builder: flatbuffers.Builder, pairs: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(pairs), 0)

def AddPairs(builder: flatbuffers.Builder, pairs: int):
    LogAddPairs(builder, pairs)

def LogStartPairsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartPairsVector(builder, numElems: int) -> int:
    return LogStartPairsVector(builder, numElems)

def LogEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return LogEnd(builder)
