# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class RawGeom(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = RawGeom()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsRawGeom(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # RawGeom
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # RawGeom
    def Geom(self, j: int):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 1))
        return 0

    # RawGeom
    def GeomAsNumpy(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Uint8Flags, o)
        return 0

    # RawGeom
    def GeomLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # RawGeom
    def GeomIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        return o == 0

def RawGeomStart(builder: flatbuffers.Builder):
    builder.StartObject(1)

def Start(builder: flatbuffers.Builder):
    RawGeomStart(builder)

def RawGeomAddGeom(builder: flatbuffers.Builder, geom: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(geom), 0)

def AddGeom(builder: flatbuffers.Builder, geom: int):
    RawGeomAddGeom(builder, geom)

def RawGeomStartGeomVector(builder, numElems: int) -> int:
    return builder.StartVector(1, numElems, 1)

def StartGeomVector(builder, numElems: int) -> int:
    return RawGeomStartGeomVector(builder, numElems)

def RawGeomEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return RawGeomEnd(builder)
