# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

# Same as Binary, but with 64-bit offsets, allowing to represent
# extremely large data values.
class LargeBinary(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = LargeBinary()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsLargeBinary(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # LargeBinary
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

def LargeBinaryStart(builder: flatbuffers.Builder):
    builder.StartObject(0)

def Start(builder: flatbuffers.Builder):
    LargeBinaryStart(builder)

def LargeBinaryEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return LargeBinaryEnd(builder)
