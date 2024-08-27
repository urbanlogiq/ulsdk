# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class GraphEdge(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = GraphEdge()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsGraphEdge(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # GraphEdge
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # GraphEdge
    def _Kind(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return 0

    # GraphEdge
    def _From(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int64Flags, o + self._tab.Pos)
        return 0

    # GraphEdge
    def _To(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int64Flags, o + self._tab.Pos)
        return 0

def GraphEdgeStart(builder: flatbuffers.Builder):
    builder.StartObject(3)

def Start(builder: flatbuffers.Builder):
    GraphEdgeStart(builder)

def GraphEdgeAdd_Kind(builder: flatbuffers.Builder, _Kind: int):
    builder.PrependInt32Slot(0, _Kind, 0)

def Add_Kind(builder: flatbuffers.Builder, _Kind: int):
    GraphEdgeAdd_Kind(builder, _Kind)

def GraphEdgeAdd_From(builder: flatbuffers.Builder, _From: int):
    builder.PrependInt64Slot(1, _From, 0)

def Add_From(builder: flatbuffers.Builder, _From: int):
    GraphEdgeAdd_From(builder, _From)

def GraphEdgeAdd_To(builder: flatbuffers.Builder, _To: int):
    builder.PrependInt64Slot(2, _To, 0)

def Add_To(builder: flatbuffers.Builder, _To: int):
    GraphEdgeAdd_To(builder, _To)

def GraphEdgeEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return GraphEdgeEnd(builder)
