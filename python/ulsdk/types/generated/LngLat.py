# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class LngLat(object):
    __slots__ = ['_tab']

    @classmethod
    def SizeOf(cls) -> int:
        return 8

    # LngLat
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # LngLat
    def Lng(self): return self._tab.Get(flatbuffers.number_types.Float32Flags, self._tab.Pos + flatbuffers.number_types.UOffsetTFlags.py_type(0))
    # LngLat
    def Lat(self): return self._tab.Get(flatbuffers.number_types.Float32Flags, self._tab.Pos + flatbuffers.number_types.UOffsetTFlags.py_type(4))

def CreateLngLat(builder, lng, lat):
    builder.Prep(4, 8)
    builder.PrependFloat32(lat)
    builder.PrependFloat32(lng)
    return builder.Offset()