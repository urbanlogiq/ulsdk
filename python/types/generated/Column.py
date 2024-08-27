# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .NullableUint import NullableUint
from typing import Optional
np = import_numpy()

class Column(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Column()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsColumn(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Column
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Column
    def Name(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Column
    def TypeHint(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int8Flags, o + self._tab.Pos)
        return 0

    # Column
    def Source(self) -> Optional[NullableUint]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = NullableUint()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

def ColumnStart(builder: flatbuffers.Builder):
    builder.StartObject(3)

def Start(builder: flatbuffers.Builder):
    ColumnStart(builder)

def ColumnAddName(builder: flatbuffers.Builder, name: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(name), 0)

def AddName(builder: flatbuffers.Builder, name: int):
    ColumnAddName(builder, name)

def ColumnAddTypeHint(builder: flatbuffers.Builder, typeHint: int):
    builder.PrependInt8Slot(1, typeHint, 0)

def AddTypeHint(builder: flatbuffers.Builder, typeHint: int):
    ColumnAddTypeHint(builder, typeHint)

def ColumnAddSource(builder: flatbuffers.Builder, source: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(source), 0)

def AddSource(builder: flatbuffers.Builder, source: int):
    ColumnAddSource(builder, source)

def ColumnEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return ColumnEnd(builder)
