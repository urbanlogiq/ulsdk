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
from .api import SortOrder
from .entity import (
    EdgeTy,
    EntityTy,
    Geometry,
    GraphEdge,
    GraphNode,
    Line,
    MultiLine,
    MultiPolygon,
    NodeTy,
    Point,
    Polygon,
)
from .fun import Fn
from .graph import (
    EdgeList,
    EdgeQuery,
    Geom,
    GeomOp,
    GraphQuery,
    NodeIdPair,
    NodeList,
    NodeQuery,
    OrderBy,
    Predicate,
    Projection,
    QueryPathElement,
    QueryPathElementUnion,
    ValueTransform,
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
from .query import (
    AllColumns,
    Arrow,
    BinaryQueryElement,
    Case,
    Column,
    DataCatalog,
    DeleteQueryElement,
    Distinct,
    Expr,
    ExprUnion,
    Function,
    Join,
    JoinTy,
    MvdbSubcollection,
    NullableUint,
    OrderByExpr,
    Parameter,
    ParameterInstance,
    ParameterSlot,
    ParameterizedQuery,
    Partition,
    Query,
    QueryElement,
    QueryElementOp,
    QueryElementUnion,
    QueryTableSource,
    RecordBatchPlaceholder,
    SetExpr,
    Subcollection,
    TableOrderBy,
    TableSource,
    TableSourceUnion,
    TypeHint,
    UnaryQueryElement,
    UnsetArgument,
    UpdateQueryElement,
    ValueIndex,
    Vector,
    When,
    Window,
    WorklogSubcollection,
)
from .value import (
    Point2D,
    Tri2D,
    VArray,
    VBool,
    VBytes,
    VChar,
    VF32,
    VF64,
    VFixedSizeBytes,
    VI16,
    VI32,
    VI64,
    VI8,
    VIsize,
    VNull,
    VStr,
    VTimestampMs,
    VTimestampMsUtc,
    VTimestampNs,
    VTimestampNsUtc,
    VTri2D,
    VU16,
    VU32,
    VU64,
    VU8,
    VUnit,
    VUsize,
    Value,
    ValueInstance,
    ValueTy,
)
from .generated.AllColumns import AllColumns as FbsAllColumns
from .generated.Arrow import Arrow as FbsArrow
from .generated.B2cId import B2cId as FbsB2cId
from .generated.Binary import Binary as FbsBinary
from .generated.BinaryQueryElement import BinaryQueryElement as FbsBinaryQueryElement
from .generated.Bool import Bool as FbsBool
from .generated.Buffer import Buffer as FbsBuffer
from .generated.Case import Case as FbsCase
from .generated.Column import Column as FbsColumn
from .generated.ColumnGroupId import ColumnGroupId as FbsColumnGroupId
from .generated.ContentId import ContentId as FbsContentId
from .generated.DataCatalog import DataCatalog as FbsDataCatalog
from .generated.DataStateId import DataStateId as FbsDataStateId
from .generated.Date import Date as FbsDate
from .generated.Decimal import Decimal as FbsDecimal
from .generated.DeleteQueryElement import DeleteQueryElement as FbsDeleteQueryElement
from .generated.DictionaryEncoding import DictionaryEncoding as FbsDictionaryEncoding
from .generated.Distinct import Distinct as FbsDistinct
from .generated.Duration import Duration as FbsDuration
from .generated.EdgeList import EdgeList as FbsEdgeList
from .generated.EdgeQuery import EdgeQuery as FbsEdgeQuery
from .generated.Expr import Expr as FbsExpr
from .generated.Field import Field as FbsField
from .generated.FixedSizeBinary import FixedSizeBinary as FbsFixedSizeBinary
from .generated.FixedSizeList import FixedSizeList as FbsFixedSizeList
from .generated.FloatingPoint import FloatingPoint as FbsFloatingPoint
from .generated.Function import Function as FbsFunction
from .generated.GenericId import GenericId as FbsGenericId
from .generated.Geom import Geom as FbsGeom
from .generated.GeomOp import GeomOp as FbsGeomOp
from .generated.GraphEdge import GraphEdge as FbsGraphEdge
from .generated.GraphNode import GraphNode as FbsGraphNode
from .generated.GraphNodeId import GraphNodeId as FbsGraphNodeId
from .generated.GraphQuery import GraphQuery as FbsGraphQuery
from .generated.Int import Int as FbsInt
from .generated.Interval import Interval as FbsInterval
from .generated.Join import Join as FbsJoin
from .generated.KeyValue import KeyValue as FbsKeyValue
from .generated.LargeBinary import LargeBinary as FbsLargeBinary
from .generated.LargeList import LargeList as FbsLargeList
from .generated.LargeUtf8 import LargeUtf8 as FbsLargeUtf8
from .generated.Line import Line as FbsLine
from .generated.List import List as FbsList
from .generated.Map import Map as FbsMap
from .generated.MultiLine import MultiLine as FbsMultiLine
from .generated.MultiPolygon import MultiPolygon as FbsMultiPolygon
from .generated.MvdbSubcollection import MvdbSubcollection as FbsMvdbSubcollection
from .generated.NodeIdPair import NodeIdPair as FbsNodeIdPair
from .generated.NodeList import NodeList as FbsNodeList
from .generated.NodeQuery import NodeQuery as FbsNodeQuery
from .generated.Null import Null as FbsNull
from .generated.NullableUint import NullableUint as FbsNullableUint
from .generated.ObjectId import ObjectId as FbsObjectId
from .generated.OrderBy import OrderBy as FbsOrderBy
from .generated.OrderByExpr import OrderByExpr as FbsOrderByExpr
from .generated.Parameter import Parameter as FbsParameter
from .generated.ParameterInstance import ParameterInstance as FbsParameterInstance
from .generated.ParameterizedQuery import ParameterizedQuery as FbsParameterizedQuery
from .generated.Partition import Partition as FbsPartition
from .generated.Point import Point as FbsPoint
from .generated.Point2D import Point2D as FbsPoint2D
from .generated.Polygon import Polygon as FbsPolygon
from .generated.Projection import Projection as FbsProjection
from .generated.Query import Query as FbsQuery
from .generated.QueryElement import QueryElement as FbsQueryElement
from .generated.QueryPathElement import QueryPathElement as FbsQueryPathElement
from .generated.QueryTableSource import QueryTableSource as FbsQueryTableSource
from .generated.RecordBatchPlaceholder import RecordBatchPlaceholder as FbsRecordBatchPlaceholder
from .generated.Schema import Schema as FbsSchema
from .generated.SetExpr import SetExpr as FbsSetExpr
from .generated.StreamId import StreamId as FbsStreamId
from .generated.Struct_ import Struct_ as FbsStruct_
from .generated.TableOrderBy import TableOrderBy as FbsTableOrderBy
from .generated.TableSource import TableSource as FbsTableSource
from .generated.Time import Time as FbsTime
from .generated.Timestamp import Timestamp as FbsTimestamp
from .generated.Tri2D import Tri2D as FbsTri2D
from .generated.UnaryQueryElement import UnaryQueryElement as FbsUnaryQueryElement
from .generated.Union import Union as FbsUnion
from .generated.UnsetArgument import UnsetArgument as FbsUnsetArgument
from .generated.UpdateQueryElement import UpdateQueryElement as FbsUpdateQueryElement
from .generated.UseCase import UseCase as FbsUseCase
from .generated.UseCaseInputPair import UseCaseInputPair as FbsUseCaseInputPair
from .generated.Utf8 import Utf8 as FbsUtf8
from .generated.VArray import VArray as FbsVArray
from .generated.VBool import VBool as FbsVBool
from .generated.VBytes import VBytes as FbsVBytes
from .generated.VChar import VChar as FbsVChar
from .generated.VF32 import VF32 as FbsVF32
from .generated.VF64 import VF64 as FbsVF64
from .generated.VFixedSizeBytes import VFixedSizeBytes as FbsVFixedSizeBytes
from .generated.VI16 import VI16 as FbsVI16
from .generated.VI32 import VI32 as FbsVI32
from .generated.VI64 import VI64 as FbsVI64
from .generated.VI8 import VI8 as FbsVI8
from .generated.VIsize import VIsize as FbsVIsize
from .generated.VNull import VNull as FbsVNull
from .generated.VStr import VStr as FbsVStr
from .generated.VTimestampMs import VTimestampMs as FbsVTimestampMs
from .generated.VTimestampMsUtc import VTimestampMsUtc as FbsVTimestampMsUtc
from .generated.VTimestampNs import VTimestampNs as FbsVTimestampNs
from .generated.VTimestampNsUtc import VTimestampNsUtc as FbsVTimestampNsUtc
from .generated.VTri2D import VTri2D as FbsVTri2D
from .generated.VU16 import VU16 as FbsVU16
from .generated.VU32 import VU32 as FbsVU32
from .generated.VU64 import VU64 as FbsVU64
from .generated.VU8 import VU8 as FbsVU8
from .generated.VUnit import VUnit as FbsVUnit
from .generated.VUsize import VUsize as FbsVUsize
from .generated.ValueIndex import ValueIndex as FbsValueIndex
from .generated.ValueInstance import ValueInstance as FbsValueInstance
from .generated.Vector import Vector as FbsVector
from .generated.When import When as FbsWhen
from .generated.Window import Window as FbsWindow
from .generated.WorklogSubcollection import WorklogSubcollection as FbsWorklogSubcollection
from .generated.ExprUnion import ExprUnion as FbsExprUnion
from .generated.Geometry import Geometry as FbsGeometry
from .generated.ParameterSlot import ParameterSlot as FbsParameterSlot
from .generated.QueryElementUnion import QueryElementUnion as FbsQueryElementUnion
from .generated.QueryPathElementUnion import QueryPathElementUnion as FbsQueryPathElementUnion
from .generated.Subcollection import Subcollection as FbsSubcollection
from .generated.TableSourceUnion import TableSourceUnion as FbsTableSourceUnion
from .generated.Type import Type as FbsType
from .generated.UseCaseInput import UseCaseInput as FbsUseCaseInput
from .generated.Value import Value as FbsValue

class UseCaseModule(Enum):
    None_ = 0
    Traffic = 1
    EconomicDevelopment = 2
    Planning = 3

class UseCaseTy(Enum):
    Invalid = 0
    OriginDestination = 1
    TrafficImpact = 2
    TxDotFreight = 3
    TravelTime = 4
    RoadVolume = 5
    IntersectionCounts = 6
    CrashBoard = 7
    TxDotCrash = 8
    HendersonDelay = 9
    PedestrianVolume = 10
    ActiveTransportation = 11
    KPIDashboard = 12
    HendersonTrafficImpact = 13
    AreaReportBulkExport = 14
    Fireboard = 15
    GenericDashboard = 16
    MetricsDashboard = 17
    FreightAnalysis = 18
    CorridorAnalysis = 19
    Ethica = 20


@dataclass
class UseCaseInput:
    value: Union[
        "ObjectId",
        "Schema",
        "ParameterizedQuery",
        "ValueInstance",
    ]

    def serialize_to(self, builder: Builder) -> Tuple[int, int]:
        from .generated.UseCaseInput import UseCaseInput
        offset = self.value.serialize_to(builder)
        if isinstance(self.value, ObjectId):
            return (offset, UseCaseInput().ObjectId)
        elif isinstance(self.value, Schema):
            return (offset, UseCaseInput().Schema)
        elif isinstance(self.value, ParameterizedQuery):
            return (offset, UseCaseInput().ParameterizedQuery)
        elif isinstance(self.value, ValueInstance):
            return (offset, UseCaseInput().ValueInstance)
        raise ValueError("Invalid union type")

    @classmethod
    def from_fbs(cls, o: Optional[Table], ty: int) -> Self:
        assert o is not None
        source = o.Bytes
        pos = o.Pos
        UseCaseInput_ty_instance = FbsUseCaseInput()
        if ty == UseCaseInput_ty_instance.ObjectId:
            val = FbsObjectId();
            val.Init(source, pos)
            return cls(ObjectId.from_fbs(val))
        elif ty == UseCaseInput_ty_instance.Schema:
            val = FbsSchema();
            val.Init(source, pos)
            return cls(Schema.from_fbs(val))
        elif ty == UseCaseInput_ty_instance.ParameterizedQuery:
            val = FbsParameterizedQuery();
            val.Init(source, pos)
            return cls(ParameterizedQuery.from_fbs(val))
        elif ty == UseCaseInput_ty_instance.ValueInstance:
            val = FbsValueInstance();
            val.Init(source, pos)
            return cls(ValueInstance.from_fbs(val))
        else:
            raise ValueError("Invalid union type")

    @classmethod
    def make_default(cls) -> Self:
        return cls(ObjectId.make_default())

    def __eq__(self, other) -> bool:
        if type(self.value) is not type(other.value):
            return False
        return self.value == other.value

@dataclass
class UseCase:
    abbreviation: Optional["str"]

    description: Optional["str"]

    extended_description: Optional["str"]

    extended_title: Optional["str"]

    inputs: "List[UseCaseInputPair]"

    module: "UseCaseModule"

    name: "str"

    subtitle: Optional["str"]

    ty: "UseCaseTy"

    @classmethod
    def from_fbs(cls, o: FbsUseCase) -> Self:
        abbreviation = None
        abbreviation_str = o.Abbreviation()
        if abbreviation_str is not None:
            abbreviation = abbreviation_str.decode('utf-8')
        description = None
        description_str = o.Description()
        if description_str is not None:
            description = description_str.decode('utf-8')
        extended_description = None
        extended_description_str = o.ExtendedDescription()
        if extended_description_str is not None:
            extended_description = extended_description_str.decode('utf-8')
        extended_title = None
        extended_title_str = o.ExtendedTitle()
        if extended_title_str is not None:
            extended_title = extended_title_str.decode('utf-8')
        inputs = list()
        if not o.InputsIsNone():
            for i in range(o.InputsLength()):
                inputs_val = None
                inputs_obj = o.Inputs(i)
                if inputs_obj is not None:
                    inputs_val = UseCaseInputPair.from_fbs(inputs_obj)
                inputs.append(inputs_val)
        module = UseCaseModule(o.Module())
        name_str = o.Name()
        assert name_str is not None
        name = name_str.decode('utf-8')
        subtitle = None
        subtitle_str = o.Subtitle()
        if subtitle_str is not None:
            subtitle = subtitle_str.decode('utf-8')
        ty = UseCaseTy(o.Ty())
        return cls(abbreviation, description, extended_description, extended_title, inputs, module, name, subtitle, ty)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsUseCase.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.UseCase import (
            Start,
            AddAbbreviation,
            AddDescription,
            AddExtendedDescription,
            AddExtendedTitle,
            AddInputs,
            StartInputsVector,
            AddModule,
            AddName,
            AddSubtitle,
            AddTy,
            End,
        )
        abbreviation_offset = None
        if self.abbreviation is not None:
            abbreviation_offset = builder.CreateString(self.abbreviation)
        description_offset = None
        if self.description is not None:
            description_offset = builder.CreateString(self.description)
        extended_description_offset = None
        if self.extended_description is not None:
            extended_description_offset = builder.CreateString(self.extended_description)
        extended_title_offset = None
        if self.extended_title is not None:
            extended_title_offset = builder.CreateString(self.extended_title)
        inputs_offsets = list()
        for value in self.inputs:
            inputs_offsets.append(value.serialize_to(builder))
        StartInputsVector(builder, len(self.inputs))
        for i in reversed(range(len(self.inputs))):
            builder.PrependUOffsetTRelative(inputs_offsets[i])
        inputs_offset = builder.EndVector()
        name_offset = builder.CreateString(self.name)
        subtitle_offset = None
        if self.subtitle is not None:
            subtitle_offset = builder.CreateString(self.subtitle)
        
        Start(builder)
        if abbreviation_offset is not None:
            AddAbbreviation(builder, abbreviation_offset)
        if description_offset is not None:
            AddDescription(builder, description_offset)
        if extended_description_offset is not None:
            AddExtendedDescription(builder, extended_description_offset)
        if extended_title_offset is not None:
            AddExtendedTitle(builder, extended_title_offset)
        AddInputs(builder, inputs_offset)
        AddModule(builder, self.module.value)
        AddName(builder, name_offset)
        if subtitle_offset is not None:
            AddSubtitle(builder, subtitle_offset)
        AddTy(builder, self.ty.value)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        abbreviation = ""
        description = ""
        extended_description = ""
        extended_title = ""
        inputs = []
        module = UseCaseModule(0)
        name = ""
        subtitle = ""
        ty = UseCaseTy(0)
        return cls(abbreviation, description, extended_description, extended_title, inputs, module, name, subtitle, ty)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.abbreviation == other.abbreviation
        eq = eq and self.description == other.description
        eq = eq and self.extended_description == other.extended_description
        eq = eq and self.extended_title == other.extended_title
        if len(self.inputs) != len(other.inputs):
            return False
        for i in range(len(self.inputs)):
            eq = eq and self.inputs[i] == other.inputs[i]
        eq = eq and self.module == other.module
        eq = eq and self.name == other.name
        eq = eq and self.subtitle == other.subtitle
        eq = eq and self.ty == other.ty

        return eq

@dataclass
class UseCaseInputPair:
    input: Optional["UseCaseInput"]

    name: "str"

    @classmethod
    def from_fbs(cls, o: FbsUseCaseInputPair) -> Self:
        input = None
        input_val = o.Input()
        if input_val is not None:
            input_ty = o.InputType()
            input = UseCaseInput.from_fbs(input_val, input_ty)
        name_str = o.Name()
        assert name_str is not None
        name = name_str.decode('utf-8')
        return cls(input, name)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsUseCaseInputPair.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.UseCaseInputPair import (
            Start,
            AddInput,
            AddInputType,
            AddName,
            End,
        )
        input_offset, input_ty = (None, None)
        if self.input is not None:
            input_offset, input_ty = self.input.serialize_to(builder)
        name_offset = builder.CreateString(self.name)
        
        Start(builder)
        if input_offset is not None and input_ty is not None:
            AddInput(builder, input_offset)
            AddInputType(builder, input_ty)
        AddName(builder, name_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        input = UseCaseInput.make_default()
        name = ""
        return cls(input, name)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.input == other.input
        eq = eq and self.name == other.name

        return eq
