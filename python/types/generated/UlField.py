# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .ValueInstance import ValueInstance
from flatbuffers.table import Table
from typing import Optional
np = import_numpy()

class UlField(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = UlField()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsUlField(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # UlField
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # UlField
    def FieldName(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # UlField
    def DisplayName(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # UlField
    def ComponentDataType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, o + self._tab.Pos)
        return 0

    # UlField
    def ComponentData(self) -> Optional[flatbuffers.table.Table]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            obj = Table(bytearray(), 0)
            self._tab.Union(obj, o)
            return obj
        return None

    # UlField
    def Flags(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # UlField
    def Unit(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # UlField
    def FieldType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(16))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # UlField
    def Description(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(18))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # UlField
    def BreakdownDisplayName(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(20))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # UlField
    def Default(self) -> Optional[ValueInstance]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(22))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ValueInstance()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # UlField
    def StorageTypeType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(24))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, o + self._tab.Pos)
        return 0

    # UlField
    def StorageType(self) -> Optional[flatbuffers.table.Table]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(26))
        if o != 0:
            obj = Table(bytearray(), 0)
            self._tab.Union(obj, o)
            return obj
        return None

def UlFieldStart(builder: flatbuffers.Builder):
    builder.StartObject(12)

def Start(builder: flatbuffers.Builder):
    UlFieldStart(builder)

def UlFieldAddFieldName(builder: flatbuffers.Builder, fieldName: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(fieldName), 0)

def AddFieldName(builder: flatbuffers.Builder, fieldName: int):
    UlFieldAddFieldName(builder, fieldName)

def UlFieldAddDisplayName(builder: flatbuffers.Builder, displayName: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(displayName), 0)

def AddDisplayName(builder: flatbuffers.Builder, displayName: int):
    UlFieldAddDisplayName(builder, displayName)

def UlFieldAddComponentDataType(builder: flatbuffers.Builder, componentDataType: int):
    builder.PrependUint8Slot(2, componentDataType, 0)

def AddComponentDataType(builder: flatbuffers.Builder, componentDataType: int):
    UlFieldAddComponentDataType(builder, componentDataType)

def UlFieldAddComponentData(builder: flatbuffers.Builder, componentData: int):
    builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(componentData), 0)

def AddComponentData(builder: flatbuffers.Builder, componentData: int):
    UlFieldAddComponentData(builder, componentData)

def UlFieldAddFlags(builder: flatbuffers.Builder, flags: int):
    builder.PrependUint32Slot(4, flags, 0)

def AddFlags(builder: flatbuffers.Builder, flags: int):
    UlFieldAddFlags(builder, flags)

def UlFieldAddUnit(builder: flatbuffers.Builder, unit: int):
    builder.PrependUint32Slot(5, unit, 0)

def AddUnit(builder: flatbuffers.Builder, unit: int):
    UlFieldAddUnit(builder, unit)

def UlFieldAddFieldType(builder: flatbuffers.Builder, fieldType: int):
    builder.PrependUint32Slot(6, fieldType, 0)

def AddFieldType(builder: flatbuffers.Builder, fieldType: int):
    UlFieldAddFieldType(builder, fieldType)

def UlFieldAddDescription(builder: flatbuffers.Builder, description: int):
    builder.PrependUOffsetTRelativeSlot(7, flatbuffers.number_types.UOffsetTFlags.py_type(description), 0)

def AddDescription(builder: flatbuffers.Builder, description: int):
    UlFieldAddDescription(builder, description)

def UlFieldAddBreakdownDisplayName(builder: flatbuffers.Builder, breakdownDisplayName: int):
    builder.PrependUOffsetTRelativeSlot(8, flatbuffers.number_types.UOffsetTFlags.py_type(breakdownDisplayName), 0)

def AddBreakdownDisplayName(builder: flatbuffers.Builder, breakdownDisplayName: int):
    UlFieldAddBreakdownDisplayName(builder, breakdownDisplayName)

def UlFieldAddDefault(builder: flatbuffers.Builder, default: int):
    builder.PrependUOffsetTRelativeSlot(9, flatbuffers.number_types.UOffsetTFlags.py_type(default), 0)

def AddDefault(builder: flatbuffers.Builder, default: int):
    UlFieldAddDefault(builder, default)

def UlFieldAddStorageTypeType(builder: flatbuffers.Builder, storageTypeType: int):
    builder.PrependUint8Slot(10, storageTypeType, 0)

def AddStorageTypeType(builder: flatbuffers.Builder, storageTypeType: int):
    UlFieldAddStorageTypeType(builder, storageTypeType)

def UlFieldAddStorageType(builder: flatbuffers.Builder, storageType: int):
    builder.PrependUOffsetTRelativeSlot(11, flatbuffers.number_types.UOffsetTFlags.py_type(storageType), 0)

def AddStorageType(builder: flatbuffers.Builder, storageType: int):
    UlFieldAddStorageType(builder, storageType)

def UlFieldEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return UlFieldEnd(builder)
