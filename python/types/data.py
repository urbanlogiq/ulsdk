# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from dataclasses import dataclass
from enum import Enum
from flatbuffers.table import Table
from flatbuffers.builder import Builder
from flatbuffers.util import RemoveSizePrefix
from typing import Union, List, Optional, Self, Tuple
from .Schema import (
    Binary,
    Bool,
    Buffer,
    Date,
    DateUnit,
    Decimal,
    DictionaryEncoding,
    DictionaryKind,
    Duration,
    Endianness,
    Feature,
    Field,
    FixedSizeBinary,
    FixedSizeList,
    FloatingPoint,
    Int,
    Interval,
    IntervalUnit,
    KeyValue,
    LargeBinary,
    LargeList,
    LargeUtf8,
    List_,
    Map,
    MetadataVersion,
    Null,
    Precision,
    Schema,
    Struct_,
    Time,
    TimeUnit,
    Timestamp,
    Type,
    Union_,
    UnionMode,
    Utf8,
)
from .id import (
    B2cId,
    ColumnGroupId,
    ContentId,
    DataStateId,
    GenericId,
    GraphNodeId,
    ObjectId,
    ObjectNamespace,
    StreamId,
)
from .reflection import (
    ReflectionAdvancedFeatures,
    ReflectionBaseType,
    ReflectionEnum,
    ReflectionEnumVal,
    ReflectionField,
    ReflectionKeyValue,
    ReflectionObject,
    ReflectionRPCCall,
    ReflectionSchema,
    ReflectionSchemaFile,
    ReflectionService,
    ReflectionType,
)
from .generated.AttributePair import AttributePair as FbsAttributePair
from .generated.B2cId import B2cId as FbsB2cId
from .generated.Binary import Binary as FbsBinary
from .generated.Bool import Bool as FbsBool
from .generated.Buffer import Buffer as FbsBuffer
from .generated.ColumnGroupId import ColumnGroupId as FbsColumnGroupId
from .generated.ContentId import ContentId as FbsContentId
from .generated.DataStateId import DataStateId as FbsDataStateId
from .generated.Date import Date as FbsDate
from .generated.Decimal import Decimal as FbsDecimal
from .generated.DictionaryEncoding import DictionaryEncoding as FbsDictionaryEncoding
from .generated.DirectionAndRoadName import DirectionAndRoadName as FbsDirectionAndRoadName
from .generated.DirectionAndRoadNames import DirectionAndRoadNames as FbsDirectionAndRoadNames
from .generated.Duration import Duration as FbsDuration
from .generated.Field import Field as FbsField
from .generated.FixedSizeBinary import FixedSizeBinary as FbsFixedSizeBinary
from .generated.FixedSizeList import FixedSizeList as FbsFixedSizeList
from .generated.FloatingPoint import FloatingPoint as FbsFloatingPoint
from .generated.GenericId import GenericId as FbsGenericId
from .generated.GraphNodeId import GraphNodeId as FbsGraphNodeId
from .generated.Int import Int as FbsInt
from .generated.Interval import Interval as FbsInterval
from .generated.KeyValue import KeyValue as FbsKeyValue
from .generated.LargeBinary import LargeBinary as FbsLargeBinary
from .generated.LargeList import LargeList as FbsLargeList
from .generated.LargeUtf8 import LargeUtf8 as FbsLargeUtf8
from .generated.List import List as FbsList
from .generated.Map import Map as FbsMap
from .generated.NamedParameter import NamedParameter as FbsNamedParameter
from .generated.Null import Null as FbsNull
from .generated.ObjectId import ObjectId as FbsObjectId
from .generated.Schema import Schema as FbsSchema
from .generated.Source import Source as FbsSource
from .generated.StreamId import StreamId as FbsStreamId
from .generated.Struct_ import Struct_ as FbsStruct_
from .generated.Time import Time as FbsTime
from .generated.Timestamp import Timestamp as FbsTimestamp
from .generated.Union import Union as FbsUnion
from .generated.Utf8 import Utf8 as FbsUtf8
from .generated.reflection.Enum import Enum as FbsEnum
from .generated.reflection.EnumVal import EnumVal as FbsEnumVal
from .generated.reflection.Field import Field as FbsField
from .generated.reflection.KeyValue import KeyValue as FbsKeyValue
from .generated.reflection.Object import Object as FbsObject
from .generated.reflection.RPCCall import RPCCall as FbsRPCCall
from .generated.reflection.Schema import Schema as FbsSchema
from .generated.reflection.SchemaFile import SchemaFile as FbsSchemaFile
from .generated.reflection.Service import Service as FbsService
from .generated.reflection.Type import Type as FbsType
from .generated.Type import Type as FbsType

class DayOfWeek(Enum):
    MONDAY = 0
    TUESDAY = 1
    WEDNESDAY = 2
    THURSDAY = 3
    FRIDAY = 4
    SATURDAY = 5
    SUNDAY = 6

class DirectionTy(Enum):
    NB = 0
    WB = 1
    SB = 2
    EB = 3
    NWB = 4
    NEB = 5
    SWB = 6
    SEB = 7
    MINUS_MP = 8
    PLUS_MP = 9
    IN = 10
    OUT = 11
    TOTAL = 12
    N = 13
    W = 14
    E = 15
    S = 16
    NW = 17
    NE = 18
    SW = 19
    SE = 20

class NamedParameterFlags(Enum):
    Value = 1
    Optional = 2

class RoadUserTy(Enum):
    BIKES = 0
    BUSES = 1
    CARS = 2
    ARTICULATED_TRUCKS = 3
    CARS_AND_LIGHT_GOODS_VEHICLES = 4
    LIGHT_GOODS_VEHICLES = 5
    SINGLE_UNIT_TRUCKS = 6
    HEAVY_VEHICLES = 7
    MOTORCYCLES = 8
    ALL_VEHICLES = 9
    TRUCKS = 10
    REGULAR_VEHICLES = 11
    MEDIUM_TRUCKS = 12
    HEAVY_TRUCKS = 13
    LIGHT_TRUCKS = 14
    LIGHT_VEHICLES = 15
    MEDIUM_VEHICLES = 16
    MULTI_UNIT_TRUCKS = 17
    TRUCKS_AND_BUSES = 18
    TRANSIT_BUSES = 19
    SCHOOL_BUSES = 20
    E_SCOOTERS = 21
    MOTORIZED_VEHICLES = 22
    CARS_AND_OTHERS = 23
    PEDS = 24
    ADULT_PEDS = 25
    CHILD_PEDS = 26
    SENIOR_PEDS = 27
    DISABLED_PEDS = 28
    BICYCLES_ON_CROSSWALK = 29
    PEDS_AND_BIKES = 30
    PHYSICALLY_CHALLENGED_PEDS = 31
    CROSSWALKS = 32
    TRAMS = 33

class StatisticTy(Enum):
    PERCENTILE_15 = 15
    PERCENTILE_20 = 20
    PERCENTILE_30 = 30
    PERCENTILE_40 = 40
    PERCENTILE_50 = 50
    PERCENTILE_85 = 85
    PERCENTILE_95 = 95
    PERCENTILE_100 = 100
    MEDIAN = 101
    MEAN = 102
    MODE = 103
    SPEED_LIMIT = 104
    STAT_MAX = 105
    STAT_MIN = 106
    MEAN_EXCEEDING = 107
    STANDARD_DEVIATION = 108
    NUMBER_OF_VEHICLES_EXCEEDING = 109

class TimeGranularity(Enum):
    NONE = 0
    Daily = 1

class TurnTy(Enum):
    CW = 0
    CCW = 1
    NONE = 2
    LEFT = 3
    RIGHT = 4
    THRU = 5
    U_TURN = 6
    BEAR_RIGHT = 7
    BEAR_LEFT = 8
    HARD_RIGHT = 9
    HARD_LEFT = 10
    RIGHT_TURNING_ON_RED = 11
    BEAR_RIGHT_ON_RED = 12


@dataclass
class AttributePair:
    key: Optional["str"]

    value: Optional["str"]

    @classmethod
    def from_fbs(cls, o: FbsAttributePair) -> Self:
        key = None
        key_str = o.Key()
        if key_str is not None:
            key = key_str.decode('utf-8')
        value = None
        value_str = o.Value()
        if value_str is not None:
            value = value_str.decode('utf-8')
        return cls(key, value)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsAttributePair.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.AttributePair import (
            Start,
            AddKey,
            AddValue,
            End,
        )
        key_offset = None
        if self.key is not None:
            key_offset = builder.CreateString(self.key)
        value_offset = None
        if self.value is not None:
            value_offset = builder.CreateString(self.value)
        
        Start(builder)
        if key_offset is not None:
            AddKey(builder, key_offset)
        if value_offset is not None:
            AddValue(builder, value_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        key = ""
        value = ""
        return cls(key, value)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.key == other.key
        eq = eq and self.value == other.value

        return eq

@dataclass
class DirectionAndRoadName:
    direction: "str"

    road_name: "str"

    @classmethod
    def from_fbs(cls, o: FbsDirectionAndRoadName) -> Self:
        direction_str = o.Direction()
        assert direction_str is not None
        direction = direction_str.decode('utf-8')
        road_name_str = o.RoadName()
        assert road_name_str is not None
        road_name = road_name_str.decode('utf-8')
        return cls(direction, road_name)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsDirectionAndRoadName.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.DirectionAndRoadName import (
            Start,
            AddDirection,
            AddRoadName,
            End,
        )
        direction_offset = builder.CreateString(self.direction)
        road_name_offset = builder.CreateString(self.road_name)
        
        Start(builder)
        AddDirection(builder, direction_offset)
        AddRoadName(builder, road_name_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        direction = ""
        road_name = ""
        return cls(direction, road_name)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.direction == other.direction
        eq = eq and self.road_name == other.road_name

        return eq

@dataclass
class DirectionAndRoadNames:
    direction_and_road_names: Optional["List[DirectionAndRoadName]"]

    @classmethod
    def from_fbs(cls, o: FbsDirectionAndRoadNames) -> Self:
        direction_and_road_names = list()
        if not o.DirectionAndRoadNamesIsNone():
            for i in range(o.DirectionAndRoadNamesLength()):
                direction_and_road_names_val = None
                direction_and_road_names_obj = o.DirectionAndRoadNames(i)
                if direction_and_road_names_obj is not None:
                    direction_and_road_names_val = DirectionAndRoadName.from_fbs(direction_and_road_names_obj)
                direction_and_road_names.append(direction_and_road_names_val)
        return cls(direction_and_road_names)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsDirectionAndRoadNames.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.DirectionAndRoadNames import (
            Start,
            AddDirectionAndRoadNames,
            StartDirectionAndRoadNamesVector,
            End,
        )
        direction_and_road_names_offset = None
        if self.direction_and_road_names is not None:
            direction_and_road_names_offsets = list()
            for value in self.direction_and_road_names:
                direction_and_road_names_offsets.append(value.serialize_to(builder))
            StartDirectionAndRoadNamesVector(builder, len(self.direction_and_road_names))
            for i in reversed(range(len(self.direction_and_road_names))):
                builder.PrependUOffsetTRelative(direction_and_road_names_offsets[i])
            direction_and_road_names_offset = builder.EndVector()
        
        Start(builder)
        if direction_and_road_names_offset is not None:
            AddDirectionAndRoadNames(builder, direction_and_road_names_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        direction_and_road_names = []
        return cls(direction_and_road_names)

    def __eq__(self, other) -> bool:
        eq = True
        self_direction_and_road_names = self.direction_and_road_names
        other_direction_and_road_names = other.direction_and_road_names
        if self_direction_and_road_names is not None and other_direction_and_road_names is not None:
            if len(self_direction_and_road_names) != len(other_direction_and_road_names):
                return False
            for i in range(len(self_direction_and_road_names)):
                eq = eq and self_direction_and_road_names[i] == other_direction_and_road_names[i]
        elif self_direction_and_road_names is not None and other_direction_and_road_names is None:
            return False
        elif self_direction_and_road_names is None and other_direction_and_road_names is not None:
            return False

        return eq

@dataclass
class NamedParameter:
    description: Optional["str"]

    flags: "int"

    name: "str"

    schema: Optional["Schema"]

    @classmethod
    def from_fbs(cls, o: FbsNamedParameter) -> Self:
        description = None
        description_str = o.Description()
        if description_str is not None:
            description = description_str.decode('utf-8')
        flags = o.Flags()
        name_str = o.Name()
        assert name_str is not None
        name = name_str.decode('utf-8')
        schema = None
        schema_obj = o.Schema()
        if schema_obj is not None:
            schema = Schema.from_fbs(schema_obj)
        return cls(description, flags, name, schema)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsNamedParameter.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.NamedParameter import (
            Start,
            AddDescription,
            AddFlags,
            AddName,
            AddSchema,
            End,
        )
        description_offset = None
        if self.description is not None:
            description_offset = builder.CreateString(self.description)
        name_offset = builder.CreateString(self.name)
        schema_offset = None
        if self.schema is not None:
            schema_offset = self.schema.serialize_to(builder)
        
        Start(builder)
        if description_offset is not None:
            AddDescription(builder, description_offset)
        AddFlags(builder, self.flags)
        AddName(builder, name_offset)
        if schema_offset is not None:
            AddSchema(builder, schema_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        description = ""
        flags = 0
        name = ""
        schema = Schema.make_default()
        return cls(description, flags, name, schema)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.description == other.description
        eq = eq and self.flags == other.flags
        eq = eq and self.name == other.name
        eq = eq and self.schema == other.schema

        return eq

@dataclass
class Source:
    metadata: Optional["ObjectId"]

    metadata_revision: Optional["ContentId"]

    name: "str"

    named_parameters: Optional["List[NamedParameter]"]

    options: Optional["List[int]"]

    schemas: Optional["List[Schema]"]

    url: "str"

    @classmethod
    def from_fbs(cls, o: FbsSource) -> Self:
        metadata = None
        metadata_obj = o.Metadata()
        if metadata_obj is not None:
            metadata = ObjectId.from_fbs(metadata_obj)
        metadata_revision = None
        metadata_revision_obj = o.MetadataRevision()
        if metadata_revision_obj is not None:
            metadata_revision = ContentId.from_fbs(metadata_revision_obj)
        name_str = o.Name()
        assert name_str is not None
        name = name_str.decode('utf-8')
        named_parameters = list()
        if not o.NamedParametersIsNone():
            for i in range(o.NamedParametersLength()):
                named_parameters_val = None
                named_parameters_obj = o.NamedParameters(i)
                if named_parameters_obj is not None:
                    named_parameters_val = NamedParameter.from_fbs(named_parameters_obj)
                named_parameters.append(named_parameters_val)
        options = list()
        if not o.OptionsIsNone():
            for i in range(o.OptionsLength()):
                options.append(o.Options(i))
        schemas = list()
        if not o.SchemasIsNone():
            for i in range(o.SchemasLength()):
                schemas_val = None
                schemas_obj = o.Schemas(i)
                if schemas_obj is not None:
                    schemas_val = Schema.from_fbs(schemas_obj)
                schemas.append(schemas_val)
        url_str = o.Url()
        assert url_str is not None
        url = url_str.decode('utf-8')
        return cls(metadata, metadata_revision, name, named_parameters, options, schemas, url)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsSource.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Source import (
            Start,
            AddMetadata,
            AddMetadataRevision,
            AddName,
            AddNamedParameters,
            StartNamedParametersVector,
            AddOptions,
            StartOptionsVector,
            AddSchemas,
            StartSchemasVector,
            AddUrl,
            End,
        )
        metadata_offset = None
        if self.metadata is not None:
            metadata_offset = self.metadata.serialize_to(builder)
        metadata_revision_offset = None
        if self.metadata_revision is not None:
            metadata_revision_offset = self.metadata_revision.serialize_to(builder)
        name_offset = builder.CreateString(self.name)
        named_parameters_offset = None
        if self.named_parameters is not None:
            named_parameters_offsets = list()
            for value in self.named_parameters:
                named_parameters_offsets.append(value.serialize_to(builder))
            StartNamedParametersVector(builder, len(self.named_parameters))
            for i in reversed(range(len(self.named_parameters))):
                builder.PrependUOffsetTRelative(named_parameters_offsets[i])
            named_parameters_offset = builder.EndVector()
        options_offset = None
        if self.options is not None:
            StartOptionsVector(builder, len(self.options))
            for i in reversed(range(len(self.options))):
                builder.PrependUint8(self.options[i])
            options_offset = builder.EndVector()
        schemas_offset = None
        if self.schemas is not None:
            schemas_offsets = list()
            for value in self.schemas:
                schemas_offsets.append(value.serialize_to(builder))
            StartSchemasVector(builder, len(self.schemas))
            for i in reversed(range(len(self.schemas))):
                builder.PrependUOffsetTRelative(schemas_offsets[i])
            schemas_offset = builder.EndVector()
        url_offset = builder.CreateString(self.url)
        
        Start(builder)
        if metadata_offset is not None:
            AddMetadata(builder, metadata_offset)
        if metadata_revision_offset is not None:
            AddMetadataRevision(builder, metadata_revision_offset)
        AddName(builder, name_offset)
        if named_parameters_offset is not None:
            AddNamedParameters(builder, named_parameters_offset)
        if options_offset is not None:
            AddOptions(builder, options_offset)
        if schemas_offset is not None:
            AddSchemas(builder, schemas_offset)
        AddUrl(builder, url_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        metadata = ObjectId.make_default()
        metadata_revision = ContentId.make_default()
        name = ""
        named_parameters = []
        options = []
        schemas = []
        url = ""
        return cls(metadata, metadata_revision, name, named_parameters, options, schemas, url)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.metadata == other.metadata
        eq = eq and self.metadata_revision == other.metadata_revision
        eq = eq and self.name == other.name
        self_named_parameters = self.named_parameters
        other_named_parameters = other.named_parameters
        if self_named_parameters is not None and other_named_parameters is not None:
            if len(self_named_parameters) != len(other_named_parameters):
                return False
            for i in range(len(self_named_parameters)):
                eq = eq and self_named_parameters[i] == other_named_parameters[i]
        elif self_named_parameters is not None and other_named_parameters is None:
            return False
        elif self_named_parameters is None and other_named_parameters is not None:
            return False
        self_options = self.options
        other_options = other.options
        if self_options is not None and other_options is not None:
            if len(self_options) != len(other_options):
                return False
            for i in range(len(self_options)):
                eq = eq and self_options[i] == other_options[i]
        elif self_options is not None and other_options is None:
            return False
        elif self_options is None and other_options is not None:
            return False
        self_schemas = self.schemas
        other_schemas = other.schemas
        if self_schemas is not None and other_schemas is not None:
            if len(self_schemas) != len(other_schemas):
                return False
            for i in range(len(self_schemas)):
                eq = eq and self_schemas[i] == other_schemas[i]
        elif self_schemas is not None and other_schemas is None:
            return False
        elif self_schemas is None and other_schemas is not None:
            return False
        eq = eq and self.url == other.url

        return eq