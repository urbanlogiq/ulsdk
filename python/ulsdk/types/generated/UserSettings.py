# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .TileData import TileData
from typing import Optional
np = import_numpy()

class UserSettings(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = UserSettings()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsUserSettings(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # UserSettings
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # UserSettings
    def TileData(self, j: int) -> Optional[TileData]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = TileData()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # UserSettings
    def TileDataLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # UserSettings
    def TileDataIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        return o == 0

    # UserSettings
    def IsTemplate(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return bool(self._tab.Get(flatbuffers.number_types.BoolFlags, o + self._tab.Pos))
        return False

def UserSettingsStart(builder: flatbuffers.Builder):
    builder.StartObject(3)

def Start(builder: flatbuffers.Builder):
    UserSettingsStart(builder)

def UserSettingsAddTileData(builder: flatbuffers.Builder, tileData: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(tileData), 0)

def AddTileData(builder: flatbuffers.Builder, tileData: int):
    UserSettingsAddTileData(builder, tileData)

def UserSettingsStartTileDataVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartTileDataVector(builder, numElems: int) -> int:
    return UserSettingsStartTileDataVector(builder, numElems)

def UserSettingsAddIsTemplate(builder: flatbuffers.Builder, isTemplate: bool):
    builder.PrependBoolSlot(2, isTemplate, 0)

def AddIsTemplate(builder: flatbuffers.Builder, isTemplate: bool):
    UserSettingsAddIsTemplate(builder, isTemplate)

def UserSettingsEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return UserSettingsEnd(builder)
