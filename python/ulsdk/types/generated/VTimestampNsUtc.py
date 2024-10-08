# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class VTimestampNsUtc(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = VTimestampNsUtc()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsVTimestampNsUtc(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # VTimestampNsUtc
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # VTimestampNsUtc
    def V(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int64Flags, o + self._tab.Pos)
        return 0

def VTimestampNsUtcStart(builder: flatbuffers.Builder):
    builder.StartObject(1)

def Start(builder: flatbuffers.Builder):
    VTimestampNsUtcStart(builder)

def VTimestampNsUtcAddV(builder: flatbuffers.Builder, v: int):
    builder.PrependInt64Slot(0, v, 0)

def AddV(builder: flatbuffers.Builder, v: int):
    VTimestampNsUtcAddV(builder, v)

def VTimestampNsUtcEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return VTimestampNsUtcEnd(builder)
