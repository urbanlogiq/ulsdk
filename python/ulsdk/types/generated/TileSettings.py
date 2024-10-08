# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .ObjectId import ObjectId
from typing import Optional
np = import_numpy()

class TileSettings(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = TileSettings()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsTileSettings(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # TileSettings
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # The column of tbe aggregation dataset to use
    # TileSettings
    def Aggregation(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # The category
    # TileSettings
    def Category(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # What chart type to display the data as
    # TileSettings
    def ChartType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # The field name from the metadata and dataset. Note that if it is a
    # relationshipField, it will use the displayName instead
    # TileSettings
    def FieldName(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Whether to group the other fields under "Other" if not showing all columns
    # TileSettings
    def GroupOthers(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            return bool(self._tab.Get(flatbuffers.number_types.BoolFlags, o + self._tab.Pos))
        return False

    # Whether it is a relationship field (or a non-associated field)
    # TileSettings
    def IsRelationshipField(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        if o != 0:
            return bool(self._tab.Get(flatbuffers.number_types.BoolFlags, o + self._tab.Pos))
        return False

    # The metadata id for the field shown
    # TileSettings
    def MetadataId(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(16))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Which output stream the report belongs to
    # TileSettings
    def OutputStreamIndex(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(18))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # Which columns the user has selected to show. If this is a relationship field, the user
    # can select which of the relationship fields to show. If it is nonassociated field, it's
    # possible that they only want to show certain ranges, which would be stored here, but
    # that isn't currently supported
    # TileSettings
    def SelectedColumns(self, j: int):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(20))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.String(a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 4))
        return ""

    # TileSettings
    def SelectedColumnsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(20))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # TileSettings
    def SelectedColumnsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(20))
        return o == 0

    # The title of the tile
    # TileSettings
    def Title(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(22))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Percentage or RawNumber
    # TileSettings
    def ValuesFormat(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(24))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # Record-count tiles report on the total number of graph nodes for the stream in the area, rather than
    # on any specific field in that stream.
    # TileSettings
    def IsRecordCountTile(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(26))
        if o != 0:
            return bool(self._tab.Get(flatbuffers.number_types.BoolFlags, o + self._tab.Pos))
        return False

    # Font size for text tiles
    # TileSettings
    def TextTileFontSize(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(28))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # TileSettings
    def RecordCountStreamId(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(30))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

def TileSettingsStart(builder: flatbuffers.Builder):
    builder.StartObject(14)

def Start(builder: flatbuffers.Builder):
    TileSettingsStart(builder)

def TileSettingsAddAggregation(builder: flatbuffers.Builder, aggregation: int):
    builder.PrependUint32Slot(0, aggregation, 0)

def AddAggregation(builder: flatbuffers.Builder, aggregation: int):
    TileSettingsAddAggregation(builder, aggregation)

def TileSettingsAddCategory(builder: flatbuffers.Builder, category: int):
    builder.PrependUint32Slot(1, category, 0)

def AddCategory(builder: flatbuffers.Builder, category: int):
    TileSettingsAddCategory(builder, category)

def TileSettingsAddChartType(builder: flatbuffers.Builder, chartType: int):
    builder.PrependUint32Slot(2, chartType, 0)

def AddChartType(builder: flatbuffers.Builder, chartType: int):
    TileSettingsAddChartType(builder, chartType)

def TileSettingsAddFieldName(builder: flatbuffers.Builder, fieldName: int):
    builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(fieldName), 0)

def AddFieldName(builder: flatbuffers.Builder, fieldName: int):
    TileSettingsAddFieldName(builder, fieldName)

def TileSettingsAddGroupOthers(builder: flatbuffers.Builder, groupOthers: bool):
    builder.PrependBoolSlot(4, groupOthers, 0)

def AddGroupOthers(builder: flatbuffers.Builder, groupOthers: bool):
    TileSettingsAddGroupOthers(builder, groupOthers)

def TileSettingsAddIsRelationshipField(builder: flatbuffers.Builder, isRelationshipField: bool):
    builder.PrependBoolSlot(5, isRelationshipField, 0)

def AddIsRelationshipField(builder: flatbuffers.Builder, isRelationshipField: bool):
    TileSettingsAddIsRelationshipField(builder, isRelationshipField)

def TileSettingsAddMetadataId(builder: flatbuffers.Builder, metadataId: int):
    builder.PrependUOffsetTRelativeSlot(6, flatbuffers.number_types.UOffsetTFlags.py_type(metadataId), 0)

def AddMetadataId(builder: flatbuffers.Builder, metadataId: int):
    TileSettingsAddMetadataId(builder, metadataId)

def TileSettingsAddOutputStreamIndex(builder: flatbuffers.Builder, outputStreamIndex: int):
    builder.PrependUint32Slot(7, outputStreamIndex, 0)

def AddOutputStreamIndex(builder: flatbuffers.Builder, outputStreamIndex: int):
    TileSettingsAddOutputStreamIndex(builder, outputStreamIndex)

def TileSettingsAddSelectedColumns(builder: flatbuffers.Builder, selectedColumns: int):
    builder.PrependUOffsetTRelativeSlot(8, flatbuffers.number_types.UOffsetTFlags.py_type(selectedColumns), 0)

def AddSelectedColumns(builder: flatbuffers.Builder, selectedColumns: int):
    TileSettingsAddSelectedColumns(builder, selectedColumns)

def TileSettingsStartSelectedColumnsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartSelectedColumnsVector(builder, numElems: int) -> int:
    return TileSettingsStartSelectedColumnsVector(builder, numElems)

def TileSettingsAddTitle(builder: flatbuffers.Builder, title: int):
    builder.PrependUOffsetTRelativeSlot(9, flatbuffers.number_types.UOffsetTFlags.py_type(title), 0)

def AddTitle(builder: flatbuffers.Builder, title: int):
    TileSettingsAddTitle(builder, title)

def TileSettingsAddValuesFormat(builder: flatbuffers.Builder, valuesFormat: int):
    builder.PrependUint32Slot(10, valuesFormat, 0)

def AddValuesFormat(builder: flatbuffers.Builder, valuesFormat: int):
    TileSettingsAddValuesFormat(builder, valuesFormat)

def TileSettingsAddIsRecordCountTile(builder: flatbuffers.Builder, isRecordCountTile: bool):
    builder.PrependBoolSlot(11, isRecordCountTile, 0)

def AddIsRecordCountTile(builder: flatbuffers.Builder, isRecordCountTile: bool):
    TileSettingsAddIsRecordCountTile(builder, isRecordCountTile)

def TileSettingsAddTextTileFontSize(builder: flatbuffers.Builder, textTileFontSize: int):
    builder.PrependUint32Slot(12, textTileFontSize, 0)

def AddTextTileFontSize(builder: flatbuffers.Builder, textTileFontSize: int):
    TileSettingsAddTextTileFontSize(builder, textTileFontSize)

def TileSettingsAddRecordCountStreamId(builder: flatbuffers.Builder, recordCountStreamId: int):
    builder.PrependUOffsetTRelativeSlot(13, flatbuffers.number_types.UOffsetTFlags.py_type(recordCountStreamId), 0)

def AddRecordCountStreamId(builder: flatbuffers.Builder, recordCountStreamId: int):
    TileSettingsAddRecordCountStreamId(builder, recordCountStreamId)

def TileSettingsEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return TileSettingsEnd(builder)
