# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class VTimestampMs(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = VTimestampMs()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsVTimestampMs(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # VTimestampMs
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # VTimestampMs
    def V(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int64Flags, o + self._tab.Pos)
        return 0

def VTimestampMsStart(builder: flatbuffers.Builder):
    builder.StartObject(1)

def Start(builder: flatbuffers.Builder):
    VTimestampMsStart(builder)

def VTimestampMsAddV(builder: flatbuffers.Builder, v: int):
    builder.PrependInt64Slot(0, v, 0)

def AddV(builder: flatbuffers.Builder, v: int):
    VTimestampMsAddV(builder, v)

def VTimestampMsEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return VTimestampMsEnd(builder)