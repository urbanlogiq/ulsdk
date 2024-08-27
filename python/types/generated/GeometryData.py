# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from flatbuffers.table import Table
from typing import Optional
np = import_numpy()

class GeometryData(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = GeometryData()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsGeometryData(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # GeometryData
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # GeometryData
    def DataType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, o + self._tab.Pos)
        return 0

    # GeometryData
    def Data(self) -> Optional[flatbuffers.table.Table]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            obj = Table(bytearray(), 0)
            self._tab.Union(obj, o)
            return obj
        return None

def GeometryDataStart(builder: flatbuffers.Builder):
    builder.StartObject(2)

def Start(builder: flatbuffers.Builder):
    GeometryDataStart(builder)

def GeometryDataAddDataType(builder: flatbuffers.Builder, dataType: int):
    builder.PrependUint8Slot(0, dataType, 0)

def AddDataType(builder: flatbuffers.Builder, dataType: int):
    GeometryDataAddDataType(builder, dataType)

def GeometryDataAddData(builder: flatbuffers.Builder, data: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(data), 0)

def AddData(builder: flatbuffers.Builder, data: int):
    GeometryDataAddData(builder, data)

def GeometryDataEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return GeometryDataEnd(builder)
