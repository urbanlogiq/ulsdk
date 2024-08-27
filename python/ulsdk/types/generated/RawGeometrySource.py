# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .RawGeometrySourceGeom import RawGeometrySourceGeom
from typing import Optional
np = import_numpy()

class RawGeometrySource(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = RawGeometrySource()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsRawGeometrySource(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # RawGeometrySource
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # RawGeometrySource
    def Geoms(self, j: int) -> Optional[RawGeometrySourceGeom]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = RawGeometrySourceGeom()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # RawGeometrySource
    def GeomsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # RawGeometrySource
    def GeomsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        return o == 0

def RawGeometrySourceStart(builder: flatbuffers.Builder):
    builder.StartObject(1)

def Start(builder: flatbuffers.Builder):
    RawGeometrySourceStart(builder)

def RawGeometrySourceAddGeoms(builder: flatbuffers.Builder, geoms: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(geoms), 0)

def AddGeoms(builder: flatbuffers.Builder, geoms: int):
    RawGeometrySourceAddGeoms(builder, geoms)

def RawGeometrySourceStartGeomsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartGeomsVector(builder, numElems: int) -> int:
    return RawGeometrySourceStartGeomsVector(builder, numElems)

def RawGeometrySourceEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return RawGeometrySourceEnd(builder)