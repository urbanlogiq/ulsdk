# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .Expr import Expr
from .Function import Function
from .OrderBy import OrderBy
from typing import Optional
np = import_numpy()

class Window(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Window()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsWindow(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Window
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Window
    def Fun(self) -> Optional[Function]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = Function()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Window
    def Partition(self, j: int) -> Optional[Expr]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = Expr()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Window
    def PartitionLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Window
    def PartitionIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        return o == 0

    # Window
    def OrderBy(self, j: int) -> Optional[OrderBy]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = OrderBy()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Window
    def OrderByLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Window
    def OrderByIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        return o == 0

def WindowStart(builder: flatbuffers.Builder):
    builder.StartObject(3)

def Start(builder: flatbuffers.Builder):
    WindowStart(builder)

def WindowAddFun(builder: flatbuffers.Builder, fun: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(fun), 0)

def AddFun(builder: flatbuffers.Builder, fun: int):
    WindowAddFun(builder, fun)

def WindowAddPartition(builder: flatbuffers.Builder, partition: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(partition), 0)

def AddPartition(builder: flatbuffers.Builder, partition: int):
    WindowAddPartition(builder, partition)

def WindowStartPartitionVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartPartitionVector(builder, numElems: int) -> int:
    return WindowStartPartitionVector(builder, numElems)

def WindowAddOrderBy(builder: flatbuffers.Builder, orderBy: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(orderBy), 0)

def AddOrderBy(builder: flatbuffers.Builder, orderBy: int):
    WindowAddOrderBy(builder, orderBy)

def WindowStartOrderByVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartOrderByVector(builder, numElems: int) -> int:
    return WindowStartOrderByVector(builder, numElems)

def WindowEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return WindowEnd(builder)
