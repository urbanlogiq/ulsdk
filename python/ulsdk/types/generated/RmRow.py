# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .GenericId import GenericId
from typing import Optional
np = import_numpy()

# The RmRow operation is used to remove a row from a table.
class RmRow(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = RmRow()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsRmRow(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # RmRow
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # The value of the ul_node_id column, which uniquely identifies the row.
    # RmRow
    def Row(self) -> Optional[GenericId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = GenericId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

def RmRowStart(builder: flatbuffers.Builder):
    builder.StartObject(1)

def Start(builder: flatbuffers.Builder):
    RmRowStart(builder)

def RmRowAddRow(builder: flatbuffers.Builder, row: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(row), 0)

def AddRow(builder: flatbuffers.Builder, row: int):
    RmRowAddRow(builder, row)

def RmRowEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return RmRowEnd(builder)