# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .TimeSpacePoint import TimeSpacePoint
from typing import Optional
np = import_numpy()

class Event(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Event()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsEvent(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Event
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Event
    def Point(self) -> Optional[TimeSpacePoint]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = TimeSpacePoint()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Event
    def Ty(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return 0

    # Event
    def Speed(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Float32Flags, o + self._tab.Pos)
        return 0.0

    # Event
    def Count(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return 0

def EventStart(builder: flatbuffers.Builder):
    builder.StartObject(4)

def Start(builder: flatbuffers.Builder):
    EventStart(builder)

def EventAddPoint(builder: flatbuffers.Builder, point: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(point), 0)

def AddPoint(builder: flatbuffers.Builder, point: int):
    EventAddPoint(builder, point)

def EventAddTy(builder: flatbuffers.Builder, ty: int):
    builder.PrependInt32Slot(1, ty, 0)

def AddTy(builder: flatbuffers.Builder, ty: int):
    EventAddTy(builder, ty)

def EventAddSpeed(builder: flatbuffers.Builder, speed: float):
    builder.PrependFloat32Slot(2, speed, 0.0)

def AddSpeed(builder: flatbuffers.Builder, speed: float):
    EventAddSpeed(builder, speed)

def EventAddCount(builder: flatbuffers.Builder, count: int):
    builder.PrependInt32Slot(3, count, 0)

def AddCount(builder: flatbuffers.Builder, count: int):
    EventAddCount(builder, count)

def EventEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return EventEnd(builder)
