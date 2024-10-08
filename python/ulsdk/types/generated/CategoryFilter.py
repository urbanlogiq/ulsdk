# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .ColumnGroupId import ColumnGroupId
from typing import Optional
np = import_numpy()

class CategoryFilter(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = CategoryFilter()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsCategoryFilter(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # CategoryFilter
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # CategoryFilter
    def ColumnGroupId(self) -> Optional[ColumnGroupId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ColumnGroupId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # CategoryFilter
    def Values(self, j: int):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.String(a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 4))
        return ""

    # CategoryFilter
    def ValuesLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # CategoryFilter
    def ValuesIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        return o == 0

    # CategoryFilter
    def Comparator(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # CategoryFilter
    def IncludeNulls(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return bool(self._tab.Get(flatbuffers.number_types.BoolFlags, o + self._tab.Pos))
        return False

def CategoryFilterStart(builder: flatbuffers.Builder):
    builder.StartObject(4)

def Start(builder: flatbuffers.Builder):
    CategoryFilterStart(builder)

def CategoryFilterAddColumnGroupId(builder: flatbuffers.Builder, columnGroupId: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(columnGroupId), 0)

def AddColumnGroupId(builder: flatbuffers.Builder, columnGroupId: int):
    CategoryFilterAddColumnGroupId(builder, columnGroupId)

def CategoryFilterAddValues(builder: flatbuffers.Builder, values: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(values), 0)

def AddValues(builder: flatbuffers.Builder, values: int):
    CategoryFilterAddValues(builder, values)

def CategoryFilterStartValuesVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartValuesVector(builder, numElems: int) -> int:
    return CategoryFilterStartValuesVector(builder, numElems)

def CategoryFilterAddComparator(builder: flatbuffers.Builder, comparator: int):
    builder.PrependUint32Slot(2, comparator, 0)

def AddComparator(builder: flatbuffers.Builder, comparator: int):
    CategoryFilterAddComparator(builder, comparator)

def CategoryFilterAddIncludeNulls(builder: flatbuffers.Builder, includeNulls: bool):
    builder.PrependBoolSlot(3, includeNulls, 0)

def AddIncludeNulls(builder: flatbuffers.Builder, includeNulls: bool):
    CategoryFilterAddIncludeNulls(builder, includeNulls)

def CategoryFilterEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return CategoryFilterEnd(builder)
