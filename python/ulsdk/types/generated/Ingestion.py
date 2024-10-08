# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .DefaultValue import DefaultValue
from .ObjectId import ObjectId
from flatbuffers.table import Table
from typing import Optional
np = import_numpy()

class Ingestion(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Ingestion()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsIngestion(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Ingestion
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # The target into which we ingest the data. This may be a stream or
    # even another Ingestion object.
    # Ingestion
    def Target(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Drive directory into which we store the ingestion log
    # Ingestion
    def Log(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Ingestion
    def TransformType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, o + self._tab.Pos)
        return 0

    # The data transformation to apply to the inbound data.
    # Ingestion
    def Transform(self) -> Optional[flatbuffers.table.Table]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            obj = Table(bytearray(), 0)
            self._tab.Union(obj, o)
            return obj
        return None

    # If the incoming data may be missing, we can specify the default
    # value here so that the transform can succeed.
    # Ingestion
    def Defaults(self, j: int) -> Optional[DefaultValue]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = DefaultValue()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Ingestion
    def DefaultsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Ingestion
    def DefaultsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        return o == 0

def IngestionStart(builder: flatbuffers.Builder):
    builder.StartObject(5)

def Start(builder: flatbuffers.Builder):
    IngestionStart(builder)

def IngestionAddTarget(builder: flatbuffers.Builder, target: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(target), 0)

def AddTarget(builder: flatbuffers.Builder, target: int):
    IngestionAddTarget(builder, target)

def IngestionAddLog(builder: flatbuffers.Builder, log: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(log), 0)

def AddLog(builder: flatbuffers.Builder, log: int):
    IngestionAddLog(builder, log)

def IngestionAddTransformType(builder: flatbuffers.Builder, transformType: int):
    builder.PrependUint8Slot(2, transformType, 0)

def AddTransformType(builder: flatbuffers.Builder, transformType: int):
    IngestionAddTransformType(builder, transformType)

def IngestionAddTransform(builder: flatbuffers.Builder, transform: int):
    builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(transform), 0)

def AddTransform(builder: flatbuffers.Builder, transform: int):
    IngestionAddTransform(builder, transform)

def IngestionAddDefaults(builder: flatbuffers.Builder, defaults: int):
    builder.PrependUOffsetTRelativeSlot(4, flatbuffers.number_types.UOffsetTFlags.py_type(defaults), 0)

def AddDefaults(builder: flatbuffers.Builder, defaults: int):
    IngestionAddDefaults(builder, defaults)

def IngestionStartDefaultsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartDefaultsVector(builder, numElems: int) -> int:
    return IngestionStartDefaultsVector(builder, numElems)

def IngestionEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return IngestionEnd(builder)
