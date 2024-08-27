# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from flatbuffers.table import Table
from typing import Optional
np = import_numpy()

class FieldFilter(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = FieldFilter()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsFieldFilter(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # FieldFilter
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # FieldFilter
    def FilterType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, o + self._tab.Pos)
        return 0

    # FieldFilter
    def Filter(self) -> Optional[flatbuffers.table.Table]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            obj = Table(bytearray(), 0)
            self._tab.Union(obj, o)
            return obj
        return None

def FieldFilterStart(builder: flatbuffers.Builder):
    builder.StartObject(2)

def Start(builder: flatbuffers.Builder):
    FieldFilterStart(builder)

def FieldFilterAddFilterType(builder: flatbuffers.Builder, filterType: int):
    builder.PrependUint8Slot(0, filterType, 0)

def AddFilterType(builder: flatbuffers.Builder, filterType: int):
    FieldFilterAddFilterType(builder, filterType)

def FieldFilterAddFilter(builder: flatbuffers.Builder, filter: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(filter), 0)

def AddFilter(builder: flatbuffers.Builder, filter: int):
    FieldFilterAddFilter(builder, filter)

def FieldFilterEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return FieldFilterEnd(builder)
