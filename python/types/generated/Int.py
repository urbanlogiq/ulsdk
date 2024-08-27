# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class Int(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Int()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsInt(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Int
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Int
    def BitWidth(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return 0

    # Int
    def IsSigned(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return bool(self._tab.Get(flatbuffers.number_types.BoolFlags, o + self._tab.Pos))
        return False

def IntStart(builder: flatbuffers.Builder):
    builder.StartObject(2)

def Start(builder: flatbuffers.Builder):
    IntStart(builder)

def IntAddBitWidth(builder: flatbuffers.Builder, bitWidth: int):
    builder.PrependInt32Slot(0, bitWidth, 0)

def AddBitWidth(builder: flatbuffers.Builder, bitWidth: int):
    IntAddBitWidth(builder, bitWidth)

def IntAddIsSigned(builder: flatbuffers.Builder, isSigned: bool):
    builder.PrependBoolSlot(1, isSigned, 0)

def AddIsSigned(builder: flatbuffers.Builder, isSigned: bool):
    IntAddIsSigned(builder, isSigned)

def IntEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return IntEnd(builder)
