# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from flatbuffers.table import Table
from typing import Optional
np = import_numpy()

class UlFieldRelationship(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = UlFieldRelationship()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsUlFieldRelationship(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # UlFieldRelationship
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # UlFieldRelationship
    def RelationshipDisplayName(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # UlFieldRelationship
    def RelationshipDataType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, o + self._tab.Pos)
        return 0

    # UlFieldRelationship
    def RelationshipData(self) -> Optional[flatbuffers.table.Table]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            obj = Table(bytearray(), 0)
            self._tab.Union(obj, o)
            return obj
        return None

def UlFieldRelationshipStart(builder: flatbuffers.Builder):
    builder.StartObject(3)

def Start(builder: flatbuffers.Builder):
    UlFieldRelationshipStart(builder)

def UlFieldRelationshipAddRelationshipDisplayName(builder: flatbuffers.Builder, relationshipDisplayName: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(relationshipDisplayName), 0)

def AddRelationshipDisplayName(builder: flatbuffers.Builder, relationshipDisplayName: int):
    UlFieldRelationshipAddRelationshipDisplayName(builder, relationshipDisplayName)

def UlFieldRelationshipAddRelationshipDataType(builder: flatbuffers.Builder, relationshipDataType: int):
    builder.PrependUint8Slot(1, relationshipDataType, 0)

def AddRelationshipDataType(builder: flatbuffers.Builder, relationshipDataType: int):
    UlFieldRelationshipAddRelationshipDataType(builder, relationshipDataType)

def UlFieldRelationshipAddRelationshipData(builder: flatbuffers.Builder, relationshipData: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(relationshipData), 0)

def AddRelationshipData(builder: flatbuffers.Builder, relationshipData: int):
    UlFieldRelationshipAddRelationshipData(builder, relationshipData)

def UlFieldRelationshipEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return UlFieldRelationshipEnd(builder)
