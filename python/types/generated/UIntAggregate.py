# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .UIntBucket import UIntBucket
from typing import Optional
np = import_numpy()

class UIntAggregate(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = UIntAggregate()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsUIntAggregate(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # UIntAggregate
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # UIntAggregate
    def Min(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint64Flags, o + self._tab.Pos)
        return 0

    # UIntAggregate
    def Max(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint64Flags, o + self._tab.Pos)
        return 0

    # UIntAggregate
    def Mean(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint64Flags, o + self._tab.Pos)
        return 0

    # UIntAggregate
    def Count(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint64Flags, o + self._tab.Pos)
        return 0

    # UIntAggregate
    def Sum(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint64Flags, o + self._tab.Pos)
        return 0

    # UIntAggregate
    def Variance(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint64Flags, o + self._tab.Pos)
        return 0

    # UIntAggregate
    def Histo(self, j: int) -> Optional[UIntBucket]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(16))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 16
            obj = UIntBucket()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # UIntAggregate
    def HistoLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(16))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # UIntAggregate
    def HistoIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(16))
        return o == 0

def UIntAggregateStart(builder: flatbuffers.Builder):
    builder.StartObject(7)

def Start(builder: flatbuffers.Builder):
    UIntAggregateStart(builder)

def UIntAggregateAddMin(builder: flatbuffers.Builder, min: int):
    builder.PrependUint64Slot(0, min, 0)

def AddMin(builder: flatbuffers.Builder, min: int):
    UIntAggregateAddMin(builder, min)

def UIntAggregateAddMax(builder: flatbuffers.Builder, max: int):
    builder.PrependUint64Slot(1, max, 0)

def AddMax(builder: flatbuffers.Builder, max: int):
    UIntAggregateAddMax(builder, max)

def UIntAggregateAddMean(builder: flatbuffers.Builder, mean: int):
    builder.PrependUint64Slot(2, mean, 0)

def AddMean(builder: flatbuffers.Builder, mean: int):
    UIntAggregateAddMean(builder, mean)

def UIntAggregateAddCount(builder: flatbuffers.Builder, count: int):
    builder.PrependUint64Slot(3, count, 0)

def AddCount(builder: flatbuffers.Builder, count: int):
    UIntAggregateAddCount(builder, count)

def UIntAggregateAddSum(builder: flatbuffers.Builder, sum: int):
    builder.PrependUint64Slot(4, sum, 0)

def AddSum(builder: flatbuffers.Builder, sum: int):
    UIntAggregateAddSum(builder, sum)

def UIntAggregateAddVariance(builder: flatbuffers.Builder, variance: int):
    builder.PrependUint64Slot(5, variance, 0)

def AddVariance(builder: flatbuffers.Builder, variance: int):
    UIntAggregateAddVariance(builder, variance)

def UIntAggregateAddHisto(builder: flatbuffers.Builder, histo: int):
    builder.PrependUOffsetTRelativeSlot(6, flatbuffers.number_types.UOffsetTFlags.py_type(histo), 0)

def AddHisto(builder: flatbuffers.Builder, histo: int):
    UIntAggregateAddHisto(builder, histo)

def UIntAggregateStartHistoVector(builder, numElems: int) -> int:
    return builder.StartVector(16, numElems, 8)

def StartHistoVector(builder, numElems: int) -> int:
    return UIntAggregateStartHistoVector(builder, numElems)

def UIntAggregateEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return UIntAggregateEnd(builder)
