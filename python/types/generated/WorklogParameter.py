# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from flatbuffers.table import Table
from typing import Optional
np = import_numpy()

class WorklogParameter(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = WorklogParameter()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsWorklogParameter(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # WorklogParameter
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # WorklogParameter
    def Key(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # WorklogParameter
    def ValueType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, o + self._tab.Pos)
        return 0

    # WorklogParameter
    def Value(self) -> Optional[flatbuffers.table.Table]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            obj = Table(bytearray(), 0)
            self._tab.Union(obj, o)
            return obj
        return None

def WorklogParameterStart(builder: flatbuffers.Builder):
    builder.StartObject(3)

def Start(builder: flatbuffers.Builder):
    WorklogParameterStart(builder)

def WorklogParameterAddKey(builder: flatbuffers.Builder, key: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(key), 0)

def AddKey(builder: flatbuffers.Builder, key: int):
    WorklogParameterAddKey(builder, key)

def WorklogParameterAddValueType(builder: flatbuffers.Builder, valueType: int):
    builder.PrependUint8Slot(1, valueType, 0)

def AddValueType(builder: flatbuffers.Builder, valueType: int):
    WorklogParameterAddValueType(builder, valueType)

def WorklogParameterAddValue(builder: flatbuffers.Builder, value: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(value), 0)

def AddValue(builder: flatbuffers.Builder, value: int):
    WorklogParameterAddValue(builder, value)

def WorklogParameterEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return WorklogParameterEnd(builder)
