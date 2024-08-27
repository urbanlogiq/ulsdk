# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class FixedSizeList(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = FixedSizeList()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsFixedSizeList(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # FixedSizeList
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Number of list items per value
    # FixedSizeList
    def ListSize(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return 0

def FixedSizeListStart(builder: flatbuffers.Builder):
    builder.StartObject(1)

def Start(builder: flatbuffers.Builder):
    FixedSizeListStart(builder)

def FixedSizeListAddListSize(builder: flatbuffers.Builder, listSize: int):
    builder.PrependInt32Slot(0, listSize, 0)

def AddListSize(builder: flatbuffers.Builder, listSize: int):
    FixedSizeListAddListSize(builder, listSize)

def FixedSizeListEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return FixedSizeListEnd(builder)
