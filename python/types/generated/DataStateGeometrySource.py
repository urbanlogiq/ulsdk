# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .DataStateId import DataStateId
from typing import Optional
np = import_numpy()

class DataStateGeometrySource(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = DataStateGeometrySource()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsDataStateGeometrySource(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # DataStateGeometrySource
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # DataStateGeometrySource
    def DataStateId(self) -> Optional[DataStateId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = DataStateId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

def DataStateGeometrySourceStart(builder: flatbuffers.Builder):
    builder.StartObject(1)

def Start(builder: flatbuffers.Builder):
    DataStateGeometrySourceStart(builder)

def DataStateGeometrySourceAddDataStateId(builder: flatbuffers.Builder, dataStateId: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(dataStateId), 0)

def AddDataStateId(builder: flatbuffers.Builder, dataStateId: int):
    DataStateGeometrySourceAddDataStateId(builder, dataStateId)

def DataStateGeometrySourceEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return DataStateGeometrySourceEnd(builder)
