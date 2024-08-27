# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from flatbuffers.table import Table
from typing import Optional
np = import_numpy()

class ValueInstance(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = ValueInstance()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsValueInstance(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # ValueInstance
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # ValueInstance
    def VType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, o + self._tab.Pos)
        return 0

    # ValueInstance
    def V(self) -> Optional[flatbuffers.table.Table]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            obj = Table(bytearray(), 0)
            self._tab.Union(obj, o)
            return obj
        return None

def ValueInstanceStart(builder: flatbuffers.Builder):
    builder.StartObject(2)

def Start(builder: flatbuffers.Builder):
    ValueInstanceStart(builder)

def ValueInstanceAddVType(builder: flatbuffers.Builder, vType: int):
    builder.PrependUint8Slot(0, vType, 0)

def AddVType(builder: flatbuffers.Builder, vType: int):
    ValueInstanceAddVType(builder, vType)

def ValueInstanceAddV(builder: flatbuffers.Builder, v: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(v), 0)

def AddV(builder: flatbuffers.Builder, v: int):
    ValueInstanceAddV(builder, v)

def ValueInstanceEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return ValueInstanceEnd(builder)
