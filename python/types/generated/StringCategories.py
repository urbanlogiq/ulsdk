# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class StringCategories(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = StringCategories()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsStringCategories(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # StringCategories
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # StringCategories
    def Categories(self, j: int):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.String(a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 4))
        return ""

    # StringCategories
    def CategoriesLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # StringCategories
    def CategoriesIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        return o == 0

def StringCategoriesStart(builder: flatbuffers.Builder):
    builder.StartObject(1)

def Start(builder: flatbuffers.Builder):
    StringCategoriesStart(builder)

def StringCategoriesAddCategories(builder: flatbuffers.Builder, categories: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(categories), 0)

def AddCategories(builder: flatbuffers.Builder, categories: int):
    StringCategoriesAddCategories(builder, categories)

def StringCategoriesStartCategoriesVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartCategoriesVector(builder, numElems: int) -> int:
    return StringCategoriesStartCategoriesVector(builder, numElems)

def StringCategoriesEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return StringCategoriesEnd(builder)
