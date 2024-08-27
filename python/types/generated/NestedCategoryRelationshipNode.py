# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class NestedCategoryRelationshipNode(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = NestedCategoryRelationshipNode()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsNestedCategoryRelationshipNode(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # NestedCategoryRelationshipNode
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # NestedCategoryRelationshipNode
    def Column(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return 0

    # NestedCategoryRelationshipNode
    def ChildColumns(self, j: int):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Int32Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 4))
        return 0

    # NestedCategoryRelationshipNode
    def ChildColumnsAsNumpy(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Int32Flags, o)
        return 0

    # NestedCategoryRelationshipNode
    def ChildColumnsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # NestedCategoryRelationshipNode
    def ChildColumnsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        return o == 0

def NestedCategoryRelationshipNodeStart(builder: flatbuffers.Builder):
    builder.StartObject(2)

def Start(builder: flatbuffers.Builder):
    NestedCategoryRelationshipNodeStart(builder)

def NestedCategoryRelationshipNodeAddColumn(builder: flatbuffers.Builder, column: int):
    builder.PrependInt32Slot(0, column, 0)

def AddColumn(builder: flatbuffers.Builder, column: int):
    NestedCategoryRelationshipNodeAddColumn(builder, column)

def NestedCategoryRelationshipNodeAddChildColumns(builder: flatbuffers.Builder, childColumns: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(childColumns), 0)

def AddChildColumns(builder: flatbuffers.Builder, childColumns: int):
    NestedCategoryRelationshipNodeAddChildColumns(builder, childColumns)

def NestedCategoryRelationshipNodeStartChildColumnsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartChildColumnsVector(builder, numElems: int) -> int:
    return NestedCategoryRelationshipNodeStartChildColumnsVector(builder, numElems)

def NestedCategoryRelationshipNodeEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return NestedCategoryRelationshipNodeEnd(builder)