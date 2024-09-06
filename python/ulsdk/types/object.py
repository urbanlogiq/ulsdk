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
from .data import (
    AttributePair,
    DayOfWeek,
    DirectionAndRoadName,
    DirectionAndRoadNames,
    DirectionTy,
    NamedParameter,
    NamedParameterFlags,
    RoadUserTy,
    Source,
    StatisticTy,
    TimeGranularity,
    TurnTy,
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
from .job import (
    DeprecatedRunSpec,
    DeprecatedTaskParameter,
    Edge,
    EmbeddedTable,
    Job,
    Node,
    ParamIndices,
    RunSpec,
    Schematic,
    Status,
    Task,
    TaskErrorTy,
    TaskList,
    TaskParameter,
    TaskParameterValue,
    TaskPriority,
    TaskRunFlags,
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
from .stream import (
    AxisType,
    FormatFlags,
    Stream,
    StreamFlags,
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
from .worklog import (
    AggregationTy,
    ByteArray,
    ChartTypeTy,
    Layout,
    ParameterFlags,
    ParameterValue,
    TileData,
    TileSettings,
    UserSettings,
    ValuesFormatTy,
    WorkLog,
    WorklogParameter,
)
from .generated.AttributePair import AttributePair as FbsAttributePair
from .generated.B2cId import B2cId as FbsB2cId
from .generated.Binary import Binary as FbsBinary
from .generated.Bool import Bool as FbsBool
from .generated.Buffer import Buffer as FbsBuffer
from .generated.ByteArray import ByteArray as FbsByteArray
from .generated.ColumnGroupId import ColumnGroupId as FbsColumnGroupId
from .generated.ContentId import ContentId as FbsContentId
from .generated.DataCatalogObject import DataCatalogObject as FbsDataCatalogObject
from .generated.DataStateId import DataStateId as FbsDataStateId
from .generated.Date import Date as FbsDate
from .generated.Decimal import Decimal as FbsDecimal
from .generated.DeprecatedRunSpec import DeprecatedRunSpec as FbsDeprecatedRunSpec
from .generated.DeprecatedTaskParameter import DeprecatedTaskParameter as FbsDeprecatedTaskParameter
from .generated.DictionaryEncoding import DictionaryEncoding as FbsDictionaryEncoding
from .generated.DirectionAndRoadName import DirectionAndRoadName as FbsDirectionAndRoadName
from .generated.DirectionAndRoadNames import DirectionAndRoadNames as FbsDirectionAndRoadNames
from .generated.Duration import Duration as FbsDuration
from .generated.Edge import Edge as FbsEdge
from .generated.EmbeddedTable import EmbeddedTable as FbsEmbeddedTable
from .generated.Field import Field as FbsField
from .generated.FixedSizeBinary import FixedSizeBinary as FbsFixedSizeBinary
from .generated.FixedSizeList import FixedSizeList as FbsFixedSizeList
from .generated.FloatingPoint import FloatingPoint as FbsFloatingPoint
from .generated.GenericId import GenericId as FbsGenericId
from .generated.GraphNodeId import GraphNodeId as FbsGraphNodeId
from .generated.Int import Int as FbsInt
from .generated.Interval import Interval as FbsInterval
from .generated.Job import Job as FbsJob
from .generated.KeyValue import KeyValue as FbsKeyValue
from .generated.LargeBinary import LargeBinary as FbsLargeBinary
from .generated.LargeList import LargeList as FbsLargeList
from .generated.LargeUtf8 import LargeUtf8 as FbsLargeUtf8
from .generated.Layout import Layout as FbsLayout
from .generated.List import List as FbsList
from .generated.Map import Map as FbsMap
from .generated.NamedParameter import NamedParameter as FbsNamedParameter
from .generated.Node import Node as FbsNode
from .generated.Null import Null as FbsNull
from .generated.ObjectId import ObjectId as FbsObjectId
from .generated.ObjectIdList import ObjectIdList as FbsObjectIdList
from .generated.ObjectIdPair import ObjectIdPair as FbsObjectIdPair
from .generated.ObjectIdPairList import ObjectIdPairList as FbsObjectIdPairList
from .generated.ObjectSummary import ObjectSummary as FbsObjectSummary
from .generated.ObjectSummaryList import ObjectSummaryList as FbsObjectSummaryList
from .generated.ParamIndices import ParamIndices as FbsParamIndices
from .generated.ParameterFlags import ParameterFlags as FbsParameterFlags
from .generated.Point2D import Point2D as FbsPoint2D
from .generated.RunSpec import RunSpec as FbsRunSpec
from .generated.Schema import Schema as FbsSchema
from .generated.Schematic import Schematic as FbsSchematic
from .generated.Source import Source as FbsSource
from .generated.Stream import Stream as FbsStream
from .generated.StreamId import StreamId as FbsStreamId
from .generated.Struct_ import Struct_ as FbsStruct_
from .generated.Task import Task as FbsTask
from .generated.TaskList import TaskList as FbsTaskList
from .generated.TaskParameter import TaskParameter as FbsTaskParameter
from .generated.TileData import TileData as FbsTileData
from .generated.TileSettings import TileSettings as FbsTileSettings
from .generated.Time import Time as FbsTime
from .generated.Timestamp import Timestamp as FbsTimestamp
from .generated.Tri2D import Tri2D as FbsTri2D
from .generated.Union import Union as FbsUnion
from .generated.UserSettings import UserSettings as FbsUserSettings
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
from .generated.ValueInstance import ValueInstance as FbsValueInstance
from .generated.WorkLog import WorkLog as FbsWorkLog
from .generated.WorklogParameter import WorklogParameter as FbsWorklogParameter
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
from .generated.ParameterValue import ParameterValue as FbsParameterValue
from .generated.TaskParameterValue import TaskParameterValue as FbsTaskParameterValue
from .generated.Type import Type as FbsType
from .generated.Value import Value as FbsValue

class DataCatalogObjectFlags(Enum):
    Generated = 1
    Encrypted = 2
    Signed = 4

class DataCatalogObjectTy(Enum):
    Invalid = 0
    WorkLog = 1
    Schematic = 2
    Node = 3
    Stream = 4
    Metadata = 5
    Source = 6
    UserProject = 7
    UseCase = 8
    UserPreferences = 9
    AccessControlList = 10
    DirectoryEntry = 11
    Notification = 12
    Model = 13
    Ingestion = 14


@dataclass
class DataCatalogObject:
    attributes: Optional["List[AttributePair]"]

    # Optional change log comment
    comment: Optional["str"]

    # Default protection mode (see PermissionTy in the permissions module).
    # Purpose is to determine what happens when an object is navigated to
    # (ie: a directory in the drive). Defaults to 0 (ie: no access)
    default_mode: "int"

    flags: "int"

    # This field is either an embedded flatbuffer containing the actual object
    # content (ie: worklog, schematic, ...) if the Encrypted flag is unset, or
    # an EncryptedObject where the obj field of the EncryptedObject table is
    # the embedded flatbuffer of the object if it is set.
    obj: "List[int]"

    # Parent nodes of this commit. To handle the cases of multiple parents (ie:
    # in cases of parallel mutation), this field allows multiple IDs to be specified.
    parents: "List[ContentId]"

    signature: Optional["List[int]"]

    tags: Optional["List[str]"]

    # UTC timestamp (in ms) when this change was made.
    time: "int"

    ty: "DataCatalogObjectTy"

    # User ID of the person committing the change.
    user: "B2cId"

    version: "int"

    @classmethod
    def from_fbs(cls, o: FbsDataCatalogObject) -> Self:
        attributes = list()
        if not o.AttributesIsNone():
            for i in range(o.AttributesLength()):
                attributes_val = None
                attributes_obj = o.Attributes(i)
                if attributes_obj is not None:
                    attributes_val = AttributePair.from_fbs(attributes_obj)
                attributes.append(attributes_val)
        comment = None
        comment_str = o.Comment()
        if comment_str is not None:
            comment = comment_str.decode('utf-8')
        default_mode = o.DefaultMode()
        flags = o.Flags()
        obj = list()
        if not o.ObjIsNone():
            for i in range(o.ObjLength()):
                obj.append(o.Obj(i))
        parents = list()
        if not o.ParentsIsNone():
            for i in range(o.ParentsLength()):
                parents_val = None
                parents_obj = o.Parents(i)
                if parents_obj is not None:
                    parents_val = ContentId.from_fbs(parents_obj)
                parents.append(parents_val)
        signature = list()
        if not o.SignatureIsNone():
            for i in range(o.SignatureLength()):
                signature.append(o.Signature(i))
        tags = list()
        if not o.TagsIsNone():
            for i in range(o.TagsLength()):
                tags.append(o.Tags(i))
        time = o.Time()
        ty = DataCatalogObjectTy(o.Ty())
        user_obj = o.User()
        if user_obj is not None:
            user = B2cId.from_fbs(user_obj)
        else:
            raise ValueError("User is required")
        version = o.Version()
        return cls(attributes, comment, default_mode, flags, obj, parents, signature, tags, time, ty, user, version)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsDataCatalogObject.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.DataCatalogObject import (
            Start,
            AddAttributes,
            StartAttributesVector,
            AddComment,
            AddDefaultMode,
            AddFlags,
            AddObj,
            StartObjVector,
            AddParents,
            StartParentsVector,
            AddSignature,
            StartSignatureVector,
            AddTags,
            StartTagsVector,
            AddTime,
            AddTy,
            AddUser,
            AddVersion,
            End,
        )
        attributes_offset = None
        if self.attributes is not None:
            attributes_offsets = list()
            for value in self.attributes:
                attributes_offsets.append(value.serialize_to(builder))
            StartAttributesVector(builder, len(self.attributes))
            for i in reversed(range(len(self.attributes))):
                builder.PrependUOffsetTRelative(attributes_offsets[i])
            attributes_offset = builder.EndVector()
        comment_offset = None
        if self.comment is not None:
            comment_offset = builder.CreateString(self.comment)
        StartObjVector(builder, len(self.obj))
        for i in reversed(range(len(self.obj))):
            builder.PrependUint8(self.obj[i])
        obj_offset = builder.EndVector()
        parents_offsets = list()
        for value in self.parents:
            parents_offsets.append(value.serialize_to(builder))
        StartParentsVector(builder, len(self.parents))
        for i in reversed(range(len(self.parents))):
            builder.PrependUOffsetTRelative(parents_offsets[i])
        parents_offset = builder.EndVector()
        signature_offset = None
        if self.signature is not None:
            StartSignatureVector(builder, len(self.signature))
            for i in reversed(range(len(self.signature))):
                builder.PrependUint8(self.signature[i])
            signature_offset = builder.EndVector()
        tags_offset = None
        if self.tags is not None:
            tags_offsets = list()
            for value in self.tags:
                tags_offsets.append(builder.CreateString(value))
            StartTagsVector(builder, len(self.tags))
            for i in reversed(range(len(self.tags))):
                builder.PrependUOffsetTRelative(tags_offsets[i])
            tags_offset = builder.EndVector()
        user_offset = self.user.serialize_to(builder)
        
        Start(builder)
        if attributes_offset is not None:
            AddAttributes(builder, attributes_offset)
        if comment_offset is not None:
            AddComment(builder, comment_offset)
        AddDefaultMode(builder, self.default_mode)
        AddFlags(builder, self.flags)
        AddObj(builder, obj_offset)
        AddParents(builder, parents_offset)
        if signature_offset is not None:
            AddSignature(builder, signature_offset)
        if tags_offset is not None:
            AddTags(builder, tags_offset)
        AddTime(builder, self.time)
        AddTy(builder, self.ty.value)
        AddUser(builder, user_offset)
        AddVersion(builder, self.version)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        attributes = []
        comment = ""
        default_mode = 0
        flags = 0
        obj = []
        parents = []
        signature = []
        tags = []
        time = 0
        ty = DataCatalogObjectTy(0)
        user = B2cId.make_default()
        version = 0
        return cls(attributes, comment, default_mode, flags, obj, parents, signature, tags, time, ty, user, version)

    def __eq__(self, other) -> bool:
        eq = True
        self_attributes = self.attributes
        other_attributes = other.attributes
        if self_attributes is not None and other_attributes is not None:
            if len(self_attributes) != len(other_attributes):
                return False
            for i in range(len(self_attributes)):
                eq = eq and self_attributes[i] == other_attributes[i]
        elif self_attributes is not None and other_attributes is None:
            return False
        elif self_attributes is None and other_attributes is not None:
            return False
        eq = eq and self.comment == other.comment
        eq = eq and self.default_mode == other.default_mode
        eq = eq and self.flags == other.flags
        if len(self.obj) != len(other.obj):
            return False
        for i in range(len(self.obj)):
            eq = eq and self.obj[i] == other.obj[i]
        if len(self.parents) != len(other.parents):
            return False
        for i in range(len(self.parents)):
            eq = eq and self.parents[i] == other.parents[i]
        self_signature = self.signature
        other_signature = other.signature
        if self_signature is not None and other_signature is not None:
            if len(self_signature) != len(other_signature):
                return False
            for i in range(len(self_signature)):
                eq = eq and self_signature[i] == other_signature[i]
        elif self_signature is not None and other_signature is None:
            return False
        elif self_signature is None and other_signature is not None:
            return False
        self_tags = self.tags
        other_tags = other.tags
        if self_tags is not None and other_tags is not None:
            if len(self_tags) != len(other_tags):
                return False
            for i in range(len(self_tags)):
                eq = eq and self_tags[i] == other_tags[i]
        elif self_tags is not None and other_tags is None:
            return False
        elif self_tags is None and other_tags is not None:
            return False
        eq = eq and self.time == other.time
        eq = eq and self.ty == other.ty
        eq = eq and self.user == other.user
        eq = eq and self.version == other.version

        return eq

@dataclass
class ObjectIdList:
    ids: "List[ObjectId]"

    @classmethod
    def from_fbs(cls, o: FbsObjectIdList) -> Self:
        ids = list()
        if not o.IdsIsNone():
            for i in range(o.IdsLength()):
                ids_val = None
                ids_obj = o.Ids(i)
                if ids_obj is not None:
                    ids_val = ObjectId.from_fbs(ids_obj)
                ids.append(ids_val)
        return cls(ids)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsObjectIdList.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.ObjectIdList import (
            Start,
            AddIds,
            StartIdsVector,
            End,
        )
        ids_offsets = list()
        for value in self.ids:
            ids_offsets.append(value.serialize_to(builder))
        StartIdsVector(builder, len(self.ids))
        for i in reversed(range(len(self.ids))):
            builder.PrependUOffsetTRelative(ids_offsets[i])
        ids_offset = builder.EndVector()
        
        Start(builder)
        AddIds(builder, ids_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        ids = []
        return cls(ids)

    def __eq__(self, other) -> bool:
        eq = True
        if len(self.ids) != len(other.ids):
            return False
        for i in range(len(self.ids)):
            eq = eq and self.ids[i] == other.ids[i]

        return eq

@dataclass
class ObjectIdPair:
    id: "ObjectId"

    object: Optional["List[int]"]

    @classmethod
    def from_fbs(cls, o: FbsObjectIdPair) -> Self:
        id_obj = o.Id()
        if id_obj is not None:
            id = ObjectId.from_fbs(id_obj)
        else:
            raise ValueError("Id is required")
        object = list()
        if not o.ObjectIsNone():
            for i in range(o.ObjectLength()):
                object.append(o.Object(i))
        return cls(id, object)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsObjectIdPair.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.ObjectIdPair import (
            Start,
            AddId,
            AddObject,
            StartObjectVector,
            End,
        )
        id_offset = self.id.serialize_to(builder)
        object_offset = None
        if self.object is not None:
            StartObjectVector(builder, len(self.object))
            for i in reversed(range(len(self.object))):
                builder.PrependUint8(self.object[i])
            object_offset = builder.EndVector()
        
        Start(builder)
        AddId(builder, id_offset)
        if object_offset is not None:
            AddObject(builder, object_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        id = ObjectId.make_default()
        object = []
        return cls(id, object)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.id == other.id
        self_object = self.object
        other_object = other.object
        if self_object is not None and other_object is not None:
            if len(self_object) != len(other_object):
                return False
            for i in range(len(self_object)):
                eq = eq and self_object[i] == other_object[i]
        elif self_object is not None and other_object is None:
            return False
        elif self_object is None and other_object is not None:
            return False

        return eq

@dataclass
class ObjectIdPairList:
    pairs: "List[ObjectIdPair]"

    @classmethod
    def from_fbs(cls, o: FbsObjectIdPairList) -> Self:
        pairs = list()
        if not o.PairsIsNone():
            for i in range(o.PairsLength()):
                pairs_val = None
                pairs_obj = o.Pairs(i)
                if pairs_obj is not None:
                    pairs_val = ObjectIdPair.from_fbs(pairs_obj)
                pairs.append(pairs_val)
        return cls(pairs)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsObjectIdPairList.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.ObjectIdPairList import (
            Start,
            AddPairs,
            StartPairsVector,
            End,
        )
        pairs_offsets = list()
        for value in self.pairs:
            pairs_offsets.append(value.serialize_to(builder))
        StartPairsVector(builder, len(self.pairs))
        for i in reversed(range(len(self.pairs))):
            builder.PrependUOffsetTRelative(pairs_offsets[i])
        pairs_offset = builder.EndVector()
        
        Start(builder)
        AddPairs(builder, pairs_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        pairs = []
        return cls(pairs)

    def __eq__(self, other) -> bool:
        eq = True
        if len(self.pairs) != len(other.pairs):
            return False
        for i in range(len(self.pairs)):
            eq = eq and self.pairs[i] == other.pairs[i]

        return eq

@dataclass
class ObjectSummary:
    acl: Optional["ObjectId"]

    drive_size: "int"

    head_revision: "ContentId"

    id: "ObjectId"

    time: "int"

    ty: "DataCatalogObjectTy"

    @classmethod
    def from_fbs(cls, o: FbsObjectSummary) -> Self:
        acl = None
        acl_obj = o.Acl()
        if acl_obj is not None:
            acl = ObjectId.from_fbs(acl_obj)
        drive_size = o.DriveSize()
        head_revision_obj = o.HeadRevision()
        if head_revision_obj is not None:
            head_revision = ContentId.from_fbs(head_revision_obj)
        else:
            raise ValueError("HeadRevision is required")
        id_obj = o.Id()
        if id_obj is not None:
            id = ObjectId.from_fbs(id_obj)
        else:
            raise ValueError("Id is required")
        time = o.Time()
        ty = DataCatalogObjectTy(o.Ty())
        return cls(acl, drive_size, head_revision, id, time, ty)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsObjectSummary.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.ObjectSummary import (
            Start,
            AddAcl,
            AddDriveSize,
            AddHeadRevision,
            AddId,
            AddTime,
            AddTy,
            End,
        )
        acl_offset = None
        if self.acl is not None:
            acl_offset = self.acl.serialize_to(builder)
        head_revision_offset = self.head_revision.serialize_to(builder)
        id_offset = self.id.serialize_to(builder)
        
        Start(builder)
        if acl_offset is not None:
            AddAcl(builder, acl_offset)
        AddDriveSize(builder, self.drive_size)
        AddHeadRevision(builder, head_revision_offset)
        AddId(builder, id_offset)
        AddTime(builder, self.time)
        AddTy(builder, self.ty.value)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        acl = ObjectId.make_default()
        drive_size = 0
        head_revision = ContentId.make_default()
        id = ObjectId.make_default()
        time = 0
        ty = DataCatalogObjectTy(0)
        return cls(acl, drive_size, head_revision, id, time, ty)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.acl == other.acl
        eq = eq and self.drive_size == other.drive_size
        eq = eq and self.head_revision == other.head_revision
        eq = eq and self.id == other.id
        eq = eq and self.time == other.time
        eq = eq and self.ty == other.ty

        return eq

@dataclass
class ObjectSummaryList:
    pairs: "List[ObjectSummary]"

    @classmethod
    def from_fbs(cls, o: FbsObjectSummaryList) -> Self:
        pairs = list()
        if not o.PairsIsNone():
            for i in range(o.PairsLength()):
                pairs_val = None
                pairs_obj = o.Pairs(i)
                if pairs_obj is not None:
                    pairs_val = ObjectSummary.from_fbs(pairs_obj)
                pairs.append(pairs_val)
        return cls(pairs)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsObjectSummaryList.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.ObjectSummaryList import (
            Start,
            AddPairs,
            StartPairsVector,
            End,
        )
        pairs_offsets = list()
        for value in self.pairs:
            pairs_offsets.append(value.serialize_to(builder))
        StartPairsVector(builder, len(self.pairs))
        for i in reversed(range(len(self.pairs))):
            builder.PrependUOffsetTRelative(pairs_offsets[i])
        pairs_offset = builder.EndVector()
        
        Start(builder)
        AddPairs(builder, pairs_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        pairs = []
        return cls(pairs)

    def __eq__(self, other) -> bool:
        eq = True
        if len(self.pairs) != len(other.pairs):
            return False
        for i in range(len(self.pairs)):
            eq = eq and self.pairs[i] == other.pairs[i]

        return eq
