# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from typing import Optional
np = import_numpy()

class Projection(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Projection()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsProjection(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Projection
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Projection
    def Predicate(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return 0

    # Projection
    def Alias(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

def ProjectionStart(builder: flatbuffers.Builder):
    builder.StartObject(2)

def Start(builder: flatbuffers.Builder):
    ProjectionStart(builder)

def ProjectionAddPredicate(builder: flatbuffers.Builder, predicate: int):
    builder.PrependInt32Slot(0, predicate, 0)

def AddPredicate(builder: flatbuffers.Builder, predicate: int):
    ProjectionAddPredicate(builder, predicate)

def ProjectionAddAlias(builder: flatbuffers.Builder, alias: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(alias), 0)

def AddAlias(builder: flatbuffers.Builder, alias: int):
    ProjectionAddAlias(builder, alias)

def ProjectionEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return ProjectionEnd(builder)