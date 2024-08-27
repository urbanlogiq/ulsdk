# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .Line import Line
from typing import Optional
np = import_numpy()

# Polygon is an array of arrays of points.
# The first array is exterior coords, following are any interior holes
class Polygon(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Polygon()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsPolygon(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Polygon
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Polygon
    def PolygonGeo(self, j: int) -> Optional[Line]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = Line()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Polygon
    def PolygonGeoLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Polygon
    def PolygonGeoIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        return o == 0

def PolygonStart(builder: flatbuffers.Builder):
    builder.StartObject(1)

def Start(builder: flatbuffers.Builder):
    PolygonStart(builder)

def PolygonAddPolygonGeo(builder: flatbuffers.Builder, polygonGeo: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(polygonGeo), 0)

def AddPolygonGeo(builder: flatbuffers.Builder, polygonGeo: int):
    PolygonAddPolygonGeo(builder, polygonGeo)

def PolygonStartPolygonGeoVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartPolygonGeoVector(builder, numElems: int) -> int:
    return PolygonStartPolygonGeoVector(builder, numElems)

def PolygonEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return PolygonEnd(builder)
