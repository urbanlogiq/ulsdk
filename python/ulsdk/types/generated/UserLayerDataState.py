# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .ColumnGroup import ColumnGroup
from .DataStateId import DataStateId
from .FieldFilter import FieldFilter
from .StreamId import StreamId
from typing import Optional
np = import_numpy()

class UserLayerDataState(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = UserLayerDataState()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsUserLayerDataState(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # UserLayerDataState
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # UserLayerDataState
    def StreamId(self) -> Optional[StreamId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = StreamId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # UserLayerDataState
    def DataStateId(self) -> Optional[DataStateId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = DataStateId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # UserLayerDataState
    def ActiveFields(self, j: int) -> Optional[ColumnGroup]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = ColumnGroup()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # UserLayerDataState
    def ActiveFieldsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # UserLayerDataState
    def ActiveFieldsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        return o == 0

    # UserLayerDataState
    def Filters(self, j: int) -> Optional[FieldFilter]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = FieldFilter()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # UserLayerDataState
    def FiltersLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # UserLayerDataState
    def FiltersIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        return o == 0

def UserLayerDataStateStart(builder: flatbuffers.Builder):
    builder.StartObject(4)

def Start(builder: flatbuffers.Builder):
    UserLayerDataStateStart(builder)

def UserLayerDataStateAddStreamId(builder: flatbuffers.Builder, streamId: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(streamId), 0)

def AddStreamId(builder: flatbuffers.Builder, streamId: int):
    UserLayerDataStateAddStreamId(builder, streamId)

def UserLayerDataStateAddDataStateId(builder: flatbuffers.Builder, dataStateId: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(dataStateId), 0)

def AddDataStateId(builder: flatbuffers.Builder, dataStateId: int):
    UserLayerDataStateAddDataStateId(builder, dataStateId)

def UserLayerDataStateAddActiveFields(builder: flatbuffers.Builder, activeFields: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(activeFields), 0)

def AddActiveFields(builder: flatbuffers.Builder, activeFields: int):
    UserLayerDataStateAddActiveFields(builder, activeFields)

def UserLayerDataStateStartActiveFieldsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartActiveFieldsVector(builder, numElems: int) -> int:
    return UserLayerDataStateStartActiveFieldsVector(builder, numElems)

def UserLayerDataStateAddFilters(builder: flatbuffers.Builder, filters: int):
    builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(filters), 0)

def AddFilters(builder: flatbuffers.Builder, filters: int):
    UserLayerDataStateAddFilters(builder, filters)

def UserLayerDataStateStartFiltersVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartFiltersVector(builder, numElems: int) -> int:
    return UserLayerDataStateStartFiltersVector(builder, numElems)

def UserLayerDataStateEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return UserLayerDataStateEnd(builder)
