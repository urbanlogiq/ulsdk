# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .Expr import Expr
from typing import Optional
np = import_numpy()

class Partition(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Partition()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsPartition(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Partition
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Partition
    def Expr(self) -> Optional[Expr]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = Expr()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

def PartitionStart(builder: flatbuffers.Builder):
    builder.StartObject(1)

def Start(builder: flatbuffers.Builder):
    PartitionStart(builder)

def PartitionAddExpr(builder: flatbuffers.Builder, expr: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(expr), 0)

def AddExpr(builder: flatbuffers.Builder, expr: int):
    PartitionAddExpr(builder, expr)

def PartitionEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return PartitionEnd(builder)