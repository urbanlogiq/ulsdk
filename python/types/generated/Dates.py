# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class Dates(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Dates()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsDates(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Dates
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Dates
    def Min(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int64Flags, o + self._tab.Pos)
        return 0

    # Dates
    def Max(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int64Flags, o + self._tab.Pos)
        return 0

    # Dates
    def UniqueValues(self, j: int):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Int64Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 8))
        return 0

    # Dates
    def UniqueValuesAsNumpy(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Int64Flags, o)
        return 0

    # Dates
    def UniqueValuesLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Dates
    def UniqueValuesIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        return o == 0

    # Dates
    def UniqueValueCounts(self, j: int):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 4))
        return 0

    # Dates
    def UniqueValueCountsAsNumpy(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Uint32Flags, o)
        return 0

    # Dates
    def UniqueValueCountsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Dates
    def UniqueValueCountsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        return o == 0

def DatesStart(builder: flatbuffers.Builder):
    builder.StartObject(4)

def Start(builder: flatbuffers.Builder):
    DatesStart(builder)

def DatesAddMin(builder: flatbuffers.Builder, min: int):
    builder.PrependInt64Slot(0, min, 0)

def AddMin(builder: flatbuffers.Builder, min: int):
    DatesAddMin(builder, min)

def DatesAddMax(builder: flatbuffers.Builder, max: int):
    builder.PrependInt64Slot(1, max, 0)

def AddMax(builder: flatbuffers.Builder, max: int):
    DatesAddMax(builder, max)

def DatesAddUniqueValues(builder: flatbuffers.Builder, uniqueValues: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(uniqueValues), 0)

def AddUniqueValues(builder: flatbuffers.Builder, uniqueValues: int):
    DatesAddUniqueValues(builder, uniqueValues)

def DatesStartUniqueValuesVector(builder, numElems: int) -> int:
    return builder.StartVector(8, numElems, 8)

def StartUniqueValuesVector(builder, numElems: int) -> int:
    return DatesStartUniqueValuesVector(builder, numElems)

def DatesAddUniqueValueCounts(builder: flatbuffers.Builder, uniqueValueCounts: int):
    builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(uniqueValueCounts), 0)

def AddUniqueValueCounts(builder: flatbuffers.Builder, uniqueValueCounts: int):
    DatesAddUniqueValueCounts(builder, uniqueValueCounts)

def DatesStartUniqueValueCountsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartUniqueValueCountsVector(builder, numElems: int) -> int:
    return DatesStartUniqueValueCountsVector(builder, numElems)

def DatesEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return DatesEnd(builder)