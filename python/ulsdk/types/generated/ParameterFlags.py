# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class ParameterFlags(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = ParameterFlags()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsParameterFlags(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # ParameterFlags
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # ParameterFlags
    def Flags(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int64Flags, o + self._tab.Pos)
        return 0

def ParameterFlagsStart(builder: flatbuffers.Builder):
    builder.StartObject(1)

def Start(builder: flatbuffers.Builder):
    ParameterFlagsStart(builder)

def ParameterFlagsAddFlags(builder: flatbuffers.Builder, flags: int):
    builder.PrependInt64Slot(0, flags, 0)

def AddFlags(builder: flatbuffers.Builder, flags: int):
    ParameterFlagsAddFlags(builder, flags)

def ParameterFlagsEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return ParameterFlagsEnd(builder)
