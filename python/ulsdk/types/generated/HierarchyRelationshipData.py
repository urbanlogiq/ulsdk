# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .HierarchicalRelationship import HierarchicalRelationship
from typing import Optional
np = import_numpy()

class HierarchyRelationshipData(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = HierarchyRelationshipData()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsHierarchyRelationshipData(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # HierarchyRelationshipData
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # HierarchyRelationshipData
    def Hierarchy(self, j: int) -> Optional[HierarchicalRelationship]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = HierarchicalRelationship()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # HierarchyRelationshipData
    def HierarchyLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # HierarchyRelationshipData
    def HierarchyIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        return o == 0

def HierarchyRelationshipDataStart(builder: flatbuffers.Builder):
    builder.StartObject(1)

def Start(builder: flatbuffers.Builder):
    HierarchyRelationshipDataStart(builder)

def HierarchyRelationshipDataAddHierarchy(builder: flatbuffers.Builder, hierarchy: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(hierarchy), 0)

def AddHierarchy(builder: flatbuffers.Builder, hierarchy: int):
    HierarchyRelationshipDataAddHierarchy(builder, hierarchy)

def HierarchyRelationshipDataStartHierarchyVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartHierarchyVector(builder, numElems: int) -> int:
    return HierarchyRelationshipDataStartHierarchyVector(builder, numElems)

def HierarchyRelationshipDataEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return HierarchyRelationshipDataEnd(builder)
