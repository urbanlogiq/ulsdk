# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class TimeSpacePoint(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = TimeSpacePoint()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsTimeSpacePoint(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # TimeSpacePoint
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # TimeSpacePoint
    def Lng(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Float32Flags, o + self._tab.Pos)
        return 0.0

    # TimeSpacePoint
    def Lat(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Float32Flags, o + self._tab.Pos)
        return 0.0

    # TimeSpacePoint
    def Timestamp(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int64Flags, o + self._tab.Pos)
        return 0

def TimeSpacePointStart(builder: flatbuffers.Builder):
    builder.StartObject(3)

def Start(builder: flatbuffers.Builder):
    TimeSpacePointStart(builder)

def TimeSpacePointAddLng(builder: flatbuffers.Builder, lng: float):
    builder.PrependFloat32Slot(0, lng, 0.0)

def AddLng(builder: flatbuffers.Builder, lng: float):
    TimeSpacePointAddLng(builder, lng)

def TimeSpacePointAddLat(builder: flatbuffers.Builder, lat: float):
    builder.PrependFloat32Slot(1, lat, 0.0)

def AddLat(builder: flatbuffers.Builder, lat: float):
    TimeSpacePointAddLat(builder, lat)

def TimeSpacePointAddTimestamp(builder: flatbuffers.Builder, timestamp: int):
    builder.PrependInt64Slot(2, timestamp, 0)

def AddTimestamp(builder: flatbuffers.Builder, timestamp: int):
    TimeSpacePointAddTimestamp(builder, timestamp)

def TimeSpacePointEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return TimeSpacePointEnd(builder)
