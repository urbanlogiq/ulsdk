# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .GenericId import GenericId
from .ObjectId import ObjectId
from .Point import Point
from flatbuffers.table import Table
from typing import Optional
np = import_numpy()

class GraphNode(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = GraphNode()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsGraphNode(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # GraphNode
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Entity type (ie: traffic loop, road, power line, building, business, demographic data, collision,  ...)
    # GraphNode
    def _EntityType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return 0

    # Node type, such as emitter vs. entity
    # GraphNode
    def _NodeType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return 0

    # ID of the associated data source
    # GraphNode
    def _Stream(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Record id in the data source.
    # GraphNode
    def _NodeId(self) -> Optional[GenericId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = GenericId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # lat/lng point in space, or centroid if not a point
    # GraphNode
    def _Location(self) -> Optional[Point]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = Point()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # GraphNode
    def _GeomType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, o + self._tab.Pos)
        return 0

    # polygon / line / point / null
    # GraphNode
    def _Geom(self) -> Optional[flatbuffers.table.Table]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(16))
        if o != 0:
            obj = Table(bytearray(), 0)
            self._tab.Union(obj, o)
            return obj
        return None

    # A human-centric description of this graph node.
    # GraphNode
    def _Description(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(18))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Unique database-specific identifier
    # GraphNode
    def _Uid(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(20))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint64Flags, o + self._tab.Pos)
        return 0

def GraphNodeStart(builder: flatbuffers.Builder):
    builder.StartObject(9)

def Start(builder: flatbuffers.Builder):
    GraphNodeStart(builder)

def GraphNodeAdd_EntityType(builder: flatbuffers.Builder, _EntityType: int):
    builder.PrependInt32Slot(0, _EntityType, 0)

def Add_EntityType(builder: flatbuffers.Builder, _EntityType: int):
    GraphNodeAdd_EntityType(builder, _EntityType)

def GraphNodeAdd_NodeType(builder: flatbuffers.Builder, _NodeType: int):
    builder.PrependInt32Slot(1, _NodeType, 0)

def Add_NodeType(builder: flatbuffers.Builder, _NodeType: int):
    GraphNodeAdd_NodeType(builder, _NodeType)

def GraphNodeAdd_Stream(builder: flatbuffers.Builder, _Stream: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(_Stream), 0)

def Add_Stream(builder: flatbuffers.Builder, _Stream: int):
    GraphNodeAdd_Stream(builder, _Stream)

def GraphNodeAdd_NodeId(builder: flatbuffers.Builder, _NodeId: int):
    builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(_NodeId), 0)

def Add_NodeId(builder: flatbuffers.Builder, _NodeId: int):
    GraphNodeAdd_NodeId(builder, _NodeId)

def GraphNodeAdd_Location(builder: flatbuffers.Builder, _Location: int):
    builder.PrependUOffsetTRelativeSlot(4, flatbuffers.number_types.UOffsetTFlags.py_type(_Location), 0)

def Add_Location(builder: flatbuffers.Builder, _Location: int):
    GraphNodeAdd_Location(builder, _Location)

def GraphNodeAdd_GeomType(builder: flatbuffers.Builder, _GeomType: int):
    builder.PrependUint8Slot(5, _GeomType, 0)

def Add_GeomType(builder: flatbuffers.Builder, _GeomType: int):
    GraphNodeAdd_GeomType(builder, _GeomType)

def GraphNodeAdd_Geom(builder: flatbuffers.Builder, _Geom: int):
    builder.PrependUOffsetTRelativeSlot(6, flatbuffers.number_types.UOffsetTFlags.py_type(_Geom), 0)

def Add_Geom(builder: flatbuffers.Builder, _Geom: int):
    GraphNodeAdd_Geom(builder, _Geom)

def GraphNodeAdd_Description(builder: flatbuffers.Builder, _Description: int):
    builder.PrependUOffsetTRelativeSlot(7, flatbuffers.number_types.UOffsetTFlags.py_type(_Description), 0)

def Add_Description(builder: flatbuffers.Builder, _Description: int):
    GraphNodeAdd_Description(builder, _Description)

def GraphNodeAdd_Uid(builder: flatbuffers.Builder, _Uid: int):
    builder.PrependUint64Slot(8, _Uid, 0)

def Add_Uid(builder: flatbuffers.Builder, _Uid: int):
    GraphNodeAdd_Uid(builder, _Uid)

def GraphNodeEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return GraphNodeEnd(builder)