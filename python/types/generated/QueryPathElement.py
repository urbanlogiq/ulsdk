# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from flatbuffers.table import Table
from typing import Optional
np = import_numpy()

class QueryPathElement(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = QueryPathElement()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsQueryPathElement(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # QueryPathElement
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # QueryPathElement
    def ElementType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, o + self._tab.Pos)
        return 0

    # QueryPathElement
    def Element(self) -> Optional[flatbuffers.table.Table]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            obj = Table(bytearray(), 0)
            self._tab.Union(obj, o)
            return obj
        return None

def QueryPathElementStart(builder: flatbuffers.Builder):
    builder.StartObject(2)

def Start(builder: flatbuffers.Builder):
    QueryPathElementStart(builder)

def QueryPathElementAddElementType(builder: flatbuffers.Builder, elementType: int):
    builder.PrependUint8Slot(0, elementType, 0)

def AddElementType(builder: flatbuffers.Builder, elementType: int):
    QueryPathElementAddElementType(builder, elementType)

def QueryPathElementAddElement(builder: flatbuffers.Builder, element: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(element), 0)

def AddElement(builder: flatbuffers.Builder, element: int):
    QueryPathElementAddElement(builder, element)

def QueryPathElementEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return QueryPathElementEnd(builder)
