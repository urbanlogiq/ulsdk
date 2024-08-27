# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from typing import Optional
np = import_numpy()

class IntegerDisplayString(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = IntegerDisplayString()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsIntegerDisplayString(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # IntegerDisplayString
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # IntegerDisplayString
    def Value(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int64Flags, o + self._tab.Pos)
        return 0

    # IntegerDisplayString
    def DisplayName(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

def IntegerDisplayStringStart(builder: flatbuffers.Builder):
    builder.StartObject(2)

def Start(builder: flatbuffers.Builder):
    IntegerDisplayStringStart(builder)

def IntegerDisplayStringAddValue(builder: flatbuffers.Builder, value: int):
    builder.PrependInt64Slot(0, value, 0)

def AddValue(builder: flatbuffers.Builder, value: int):
    IntegerDisplayStringAddValue(builder, value)

def IntegerDisplayStringAddDisplayName(builder: flatbuffers.Builder, displayName: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(displayName), 0)

def AddDisplayName(builder: flatbuffers.Builder, displayName: int):
    IntegerDisplayStringAddDisplayName(builder, displayName)

def IntegerDisplayStringEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return IntegerDisplayStringEnd(builder)