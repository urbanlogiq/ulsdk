# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from dataclasses import dataclass
from enum import Enum
from flatbuffers.table import Table
from flatbuffers.builder import Builder
from flatbuffers.util import RemoveSizePrefix
from typing import Union, List, Optional, Self, Tuple
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
from .generated.B2cId import B2cId as FbsB2cId
from .generated.ColumnGroupId import ColumnGroupId as FbsColumnGroupId
from .generated.ContentId import ContentId as FbsContentId
from .generated.DataStateId import DataStateId as FbsDataStateId
from .generated.EdgeList import EdgeList as FbsEdgeList
from .generated.EdgeQuery import EdgeQuery as FbsEdgeQuery
from .generated.GenericId import GenericId as FbsGenericId
from .generated.Geom import Geom as FbsGeom
from .generated.GeomOp import GeomOp as FbsGeomOp
from .generated.GraphEdge import GraphEdge as FbsGraphEdge
from .generated.GraphNode import GraphNode as FbsGraphNode
from .generated.GraphNodeId import GraphNodeId as FbsGraphNodeId
from .generated.GraphQuery import GraphQuery as FbsGraphQuery
from .generated.Line import Line as FbsLine
from .generated.MultiLine import MultiLine as FbsMultiLine
from .generated.MultiPolygon import MultiPolygon as FbsMultiPolygon
from .generated.NodeIdPair import NodeIdPair as FbsNodeIdPair
from .generated.NodeList import NodeList as FbsNodeList
from .generated.NodeQuery import NodeQuery as FbsNodeQuery
from .generated.ObjectId import ObjectId as FbsObjectId
from .generated.OrderBy import OrderBy as FbsOrderBy
from .generated.Point import Point as FbsPoint
from .generated.Polygon import Polygon as FbsPolygon
from .generated.Projection import Projection as FbsProjection
from .generated.QueryPathElement import QueryPathElement as FbsQueryPathElement
from .generated.StreamId import StreamId as FbsStreamId
from .generated.Geometry import Geometry as FbsGeometry
from .generated.QueryPathElementUnion import QueryPathElementUnion as FbsQueryPathElementUnion

class Predicate(Enum):
    NONE = 0
    id = 1
    stream = 2
    node_id = 3
    entity_ty = 4
    node_ty = 5
    description = 6
    location = 7
    geom = 8

class ValueTransform(Enum):
    NONE = 0
    UuidToBase64 = 1


@dataclass
class GeomOp:
    geoms: "List[Geom]"

    op: "Fn"

    predicate: "Predicate"

    @classmethod
    def from_fbs(cls, o: FbsGeomOp) -> Self:
        geoms = list()
        if not o.GeomsIsNone():
            for i in range(o.GeomsLength()):
                geoms_val = None
                geoms_obj = o.Geoms(i)
                if geoms_obj is not None:
                    geoms_val = Geom.from_fbs(geoms_obj)
                geoms.append(geoms_val)
        op = Fn(o.Op())
        predicate = Predicate(o.Predicate())
        return cls(geoms, op, predicate)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsGeomOp.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.GeomOp import (
            Start,
            AddGeoms,
            StartGeomsVector,
            AddOp,
            AddPredicate,
            End,
        )
        geoms_offsets = list()
        for value in self.geoms:
            geoms_offsets.append(value.serialize_to(builder))
        StartGeomsVector(builder, len(self.geoms))
        for i in reversed(range(len(self.geoms))):
            builder.PrependUOffsetTRelative(geoms_offsets[i])
        geoms_offset = builder.EndVector()
        
        Start(builder)
        AddGeoms(builder, geoms_offset)
        AddOp(builder, self.op.value)
        AddPredicate(builder, self.predicate.value)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        geoms = []
        op = Fn(0)
        predicate = Predicate(0)
        return cls(geoms, op, predicate)

    def __eq__(self, other) -> bool:
        eq = True
        if len(self.geoms) != len(other.geoms):
            return False
        for i in range(len(self.geoms)):
            eq = eq and self.geoms[i] == other.geoms[i]
        eq = eq and self.op == other.op
        eq = eq and self.predicate == other.predicate

        return eq

@dataclass
class NodeQuery:
    # If descriptions are provided here, then results will be ordered by their string similarity to the
    # descriptions here. This ordering is secondary to the any top-level order_by that might be provided.
    descriptions: Optional["List[str]"]

    entity_tys: Optional["List[EntityTy]"]

    geom_op: Optional["GeomOp"]

    node_ids: Optional["List[NodeIdPair]"]

    projections: Optional["List[Projection]"]

    stream_ids: Optional["List[ObjectId]"]

    @classmethod
    def from_fbs(cls, o: FbsNodeQuery) -> Self:
        descriptions = list()
        if not o.DescriptionsIsNone():
            for i in range(o.DescriptionsLength()):
                descriptions.append(o.Descriptions(i))
        entity_tys = list()
        if not o.EntityTysIsNone():
            for i in range(o.EntityTysLength()):
                entity_tys.append(o.EntityTys(i))
        geom_op = None
        geom_op_obj = o.GeomOp()
        if geom_op_obj is not None:
            geom_op = GeomOp.from_fbs(geom_op_obj)
        node_ids = list()
        if not o.NodeIdsIsNone():
            for i in range(o.NodeIdsLength()):
                node_ids_val = None
                node_ids_obj = o.NodeIds(i)
                if node_ids_obj is not None:
                    node_ids_val = NodeIdPair.from_fbs(node_ids_obj)
                node_ids.append(node_ids_val)
        projections = list()
        if not o.ProjectionsIsNone():
            for i in range(o.ProjectionsLength()):
                projections_val = None
                projections_obj = o.Projections(i)
                if projections_obj is not None:
                    projections_val = Projection.from_fbs(projections_obj)
                projections.append(projections_val)
        stream_ids = list()
        if not o.StreamIdsIsNone():
            for i in range(o.StreamIdsLength()):
                stream_ids_val = None
                stream_ids_obj = o.StreamIds(i)
                if stream_ids_obj is not None:
                    stream_ids_val = ObjectId.from_fbs(stream_ids_obj)
                stream_ids.append(stream_ids_val)
        return cls(descriptions, entity_tys, geom_op, node_ids, projections, stream_ids)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsNodeQuery.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.NodeQuery import (
            Start,
            AddDescriptions,
            StartDescriptionsVector,
            AddEntityTys,
            StartEntityTysVector,
            AddGeomOp,
            AddNodeIds,
            StartNodeIdsVector,
            AddProjections,
            StartProjectionsVector,
            AddStreamIds,
            StartStreamIdsVector,
            End,
        )
        descriptions_offset = None
        if self.descriptions is not None:
            descriptions_offsets = list()
            for value in self.descriptions:
                descriptions_offsets.append(builder.CreateString(value))
            StartDescriptionsVector(builder, len(self.descriptions))
            for i in reversed(range(len(self.descriptions))):
                builder.PrependUOffsetTRelative(descriptions_offsets[i])
            descriptions_offset = builder.EndVector()
        entity_tys_offset = None
        if self.entity_tys is not None:
            StartEntityTysVector(builder, len(self.entity_tys))
            for i in reversed(range(len(self.entity_tys))):
                builder.PrependInt32(self.entity_tys[i])
            entity_tys_offset = builder.EndVector()
        geom_op_offset = None
        if self.geom_op is not None:
            geom_op_offset = self.geom_op.serialize_to(builder)
        node_ids_offset = None
        if self.node_ids is not None:
            node_ids_offsets = list()
            for value in self.node_ids:
                node_ids_offsets.append(value.serialize_to(builder))
            StartNodeIdsVector(builder, len(self.node_ids))
            for i in reversed(range(len(self.node_ids))):
                builder.PrependUOffsetTRelative(node_ids_offsets[i])
            node_ids_offset = builder.EndVector()
        projections_offset = None
        if self.projections is not None:
            projections_offsets = list()
            for value in self.projections:
                projections_offsets.append(value.serialize_to(builder))
            StartProjectionsVector(builder, len(self.projections))
            for i in reversed(range(len(self.projections))):
                builder.PrependUOffsetTRelative(projections_offsets[i])
            projections_offset = builder.EndVector()
        stream_ids_offset = None
        if self.stream_ids is not None:
            stream_ids_offsets = list()
            for value in self.stream_ids:
                stream_ids_offsets.append(value.serialize_to(builder))
            StartStreamIdsVector(builder, len(self.stream_ids))
            for i in reversed(range(len(self.stream_ids))):
                builder.PrependUOffsetTRelative(stream_ids_offsets[i])
            stream_ids_offset = builder.EndVector()
        
        Start(builder)
        if descriptions_offset is not None:
            AddDescriptions(builder, descriptions_offset)
        if entity_tys_offset is not None:
            AddEntityTys(builder, entity_tys_offset)
        if geom_op_offset is not None:
            AddGeomOp(builder, geom_op_offset)
        if node_ids_offset is not None:
            AddNodeIds(builder, node_ids_offset)
        if projections_offset is not None:
            AddProjections(builder, projections_offset)
        if stream_ids_offset is not None:
            AddStreamIds(builder, stream_ids_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        descriptions = []
        entity_tys = []
        geom_op = GeomOp.make_default()
        node_ids = []
        projections = []
        stream_ids = []
        return cls(descriptions, entity_tys, geom_op, node_ids, projections, stream_ids)

    def __eq__(self, other) -> bool:
        eq = True
        self_descriptions = self.descriptions
        other_descriptions = other.descriptions
        if self_descriptions is not None and other_descriptions is not None:
            if len(self_descriptions) != len(other_descriptions):
                return False
            for i in range(len(self_descriptions)):
                eq = eq and self_descriptions[i] == other_descriptions[i]
        elif self_descriptions is not None and other_descriptions is None:
            return False
        elif self_descriptions is None and other_descriptions is not None:
            return False
        self_entity_tys = self.entity_tys
        other_entity_tys = other.entity_tys
        if self_entity_tys is not None and other_entity_tys is not None:
            if len(self_entity_tys) != len(other_entity_tys):
                return False
            for i in range(len(self_entity_tys)):
                eq = eq and self_entity_tys[i] == other_entity_tys[i]
        elif self_entity_tys is not None and other_entity_tys is None:
            return False
        elif self_entity_tys is None and other_entity_tys is not None:
            return False
        eq = eq and self.geom_op == other.geom_op
        self_node_ids = self.node_ids
        other_node_ids = other.node_ids
        if self_node_ids is not None and other_node_ids is not None:
            if len(self_node_ids) != len(other_node_ids):
                return False
            for i in range(len(self_node_ids)):
                eq = eq and self_node_ids[i] == other_node_ids[i]
        elif self_node_ids is not None and other_node_ids is None:
            return False
        elif self_node_ids is None and other_node_ids is not None:
            return False
        self_projections = self.projections
        other_projections = other.projections
        if self_projections is not None and other_projections is not None:
            if len(self_projections) != len(other_projections):
                return False
            for i in range(len(self_projections)):
                eq = eq and self_projections[i] == other_projections[i]
        elif self_projections is not None and other_projections is None:
            return False
        elif self_projections is None and other_projections is not None:
            return False
        self_stream_ids = self.stream_ids
        other_stream_ids = other.stream_ids
        if self_stream_ids is not None and other_stream_ids is not None:
            if len(self_stream_ids) != len(other_stream_ids):
                return False
            for i in range(len(self_stream_ids)):
                eq = eq and self_stream_ids[i] == other_stream_ids[i]
        elif self_stream_ids is not None and other_stream_ids is None:
            return False
        elif self_stream_ids is None and other_stream_ids is not None:
            return False

        return eq

@dataclass
class EdgeQuery:
    edge_ty: "EdgeTy"

    @classmethod
    def from_fbs(cls, o: FbsEdgeQuery) -> Self:
        edge_ty = EdgeTy(o.EdgeTy())
        return cls(edge_ty)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsEdgeQuery.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.EdgeQuery import (
            Start,
            AddEdgeTy,
            End,
        )
        
        Start(builder)
        AddEdgeTy(builder, self.edge_ty.value)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        edge_ty = EdgeTy(0)
        return cls(edge_ty)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.edge_ty == other.edge_ty

        return eq

@dataclass
class QueryPathElementUnion:
    value: Union[
        "NodeQuery",
        "EdgeQuery",
    ]

    def serialize_to(self, builder: Builder) -> Tuple[int, int]:
        from .generated.QueryPathElementUnion import QueryPathElementUnion
        offset = self.value.serialize_to(builder)
        if isinstance(self.value, NodeQuery):
            return (offset, QueryPathElementUnion().NodeQuery)
        elif isinstance(self.value, EdgeQuery):
            return (offset, QueryPathElementUnion().EdgeQuery)
        raise ValueError("Invalid union type")

    @classmethod
    def from_fbs(cls, o: Optional[Table], ty: int) -> Self:
        assert o is not None
        source = o.Bytes
        pos = o.Pos
        QueryPathElementUnion_ty_instance = FbsQueryPathElementUnion()
        if ty == QueryPathElementUnion_ty_instance.NodeQuery:
            val = FbsNodeQuery();
            val.Init(source, pos)
            return cls(NodeQuery.from_fbs(val))
        elif ty == QueryPathElementUnion_ty_instance.EdgeQuery:
            val = FbsEdgeQuery();
            val.Init(source, pos)
            return cls(EdgeQuery.from_fbs(val))
        else:
            raise ValueError("Invalid union type")

    @classmethod
    def make_default(cls) -> Self:
        return cls(NodeQuery.make_default())

    def __eq__(self, other) -> bool:
        if type(self.value) is not type(other.value):
            return False
        return self.value == other.value

@dataclass
class EdgeList:
    edges: "List[GraphEdge]"

    @classmethod
    def from_fbs(cls, o: FbsEdgeList) -> Self:
        edges = list()
        if not o.EdgesIsNone():
            for i in range(o.EdgesLength()):
                edges_val = None
                edges_obj = o.Edges(i)
                if edges_obj is not None:
                    edges_val = GraphEdge.from_fbs(edges_obj)
                edges.append(edges_val)
        return cls(edges)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsEdgeList.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.EdgeList import (
            Start,
            AddEdges,
            StartEdgesVector,
            End,
        )
        edges_offsets = list()
        for value in self.edges:
            edges_offsets.append(value.serialize_to(builder))
        StartEdgesVector(builder, len(self.edges))
        for i in reversed(range(len(self.edges))):
            builder.PrependUOffsetTRelative(edges_offsets[i])
        edges_offset = builder.EndVector()
        
        Start(builder)
        AddEdges(builder, edges_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        edges = []
        return cls(edges)

    def __eq__(self, other) -> bool:
        eq = True
        if len(self.edges) != len(other.edges):
            return False
        for i in range(len(self.edges)):
            eq = eq and self.edges[i] == other.edges[i]

        return eq

@dataclass
class Geom:
    geom: "Geometry"

    @classmethod
    def from_fbs(cls, o: FbsGeom) -> Self:
        geom_val = o.Geom()
        if geom_val is not None:
            geom_ty = o.GeomType()
            geom = Geometry.from_fbs(geom_val, geom_ty)
        else:
            raise ValueError("Geom is required")
        return cls(geom)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsGeom.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Geom import (
            Start,
            AddGeom,
            AddGeomType,
            End,
        )
        geom_offset, geom_ty = self.geom.serialize_to(builder)
        
        Start(builder)
        AddGeom(builder, geom_offset)
        AddGeomType(builder, geom_ty)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        geom = Geometry.make_default()
        return cls(geom)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.geom == other.geom

        return eq

@dataclass
class GraphQuery:
    """ The GraphQuery encapsulates the entire world graph query.
    """

    limit: "int"

    order_by: Optional["List[OrderBy]"]

    path: "List[QueryPathElement]"

    @classmethod
    def from_fbs(cls, o: FbsGraphQuery) -> Self:
        limit = o.Limit()
        order_by = list()
        if not o.OrderByIsNone():
            for i in range(o.OrderByLength()):
                order_by_val = None
                order_by_obj = o.OrderBy(i)
                if order_by_obj is not None:
                    order_by_val = OrderBy.from_fbs(order_by_obj)
                order_by.append(order_by_val)
        path = list()
        if not o.PathIsNone():
            for i in range(o.PathLength()):
                path_val = None
                path_obj = o.Path(i)
                if path_obj is not None:
                    path_val = QueryPathElement.from_fbs(path_obj)
                path.append(path_val)
        return cls(limit, order_by, path)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsGraphQuery.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.GraphQuery import (
            Start,
            AddLimit,
            AddOrderBy,
            StartOrderByVector,
            AddPath,
            StartPathVector,
            End,
        )
        order_by_offset = None
        if self.order_by is not None:
            order_by_offsets = list()
            for value in self.order_by:
                order_by_offsets.append(value.serialize_to(builder))
            StartOrderByVector(builder, len(self.order_by))
            for i in reversed(range(len(self.order_by))):
                builder.PrependUOffsetTRelative(order_by_offsets[i])
            order_by_offset = builder.EndVector()
        path_offsets = list()
        for value in self.path:
            path_offsets.append(value.serialize_to(builder))
        StartPathVector(builder, len(self.path))
        for i in reversed(range(len(self.path))):
            builder.PrependUOffsetTRelative(path_offsets[i])
        path_offset = builder.EndVector()
        
        Start(builder)
        AddLimit(builder, self.limit)
        if order_by_offset is not None:
            AddOrderBy(builder, order_by_offset)
        AddPath(builder, path_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        limit = 0
        order_by = []
        path = []
        return cls(limit, order_by, path)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.limit == other.limit
        self_order_by = self.order_by
        other_order_by = other.order_by
        if self_order_by is not None and other_order_by is not None:
            if len(self_order_by) != len(other_order_by):
                return False
            for i in range(len(self_order_by)):
                eq = eq and self_order_by[i] == other_order_by[i]
        elif self_order_by is not None and other_order_by is None:
            return False
        elif self_order_by is None and other_order_by is not None:
            return False
        if len(self.path) != len(other.path):
            return False
        for i in range(len(self.path)):
            eq = eq and self.path[i] == other.path[i]

        return eq

@dataclass
class NodeIdPair:
    node_id: "GraphNodeId"

    stream_id: Optional["ObjectId"]

    @classmethod
    def from_fbs(cls, o: FbsNodeIdPair) -> Self:
        node_id_obj = o.NodeId()
        if node_id_obj is not None:
            node_id = GraphNodeId.from_fbs(node_id_obj)
        else:
            raise ValueError("NodeId is required")
        stream_id = None
        stream_id_obj = o.StreamId()
        if stream_id_obj is not None:
            stream_id = ObjectId.from_fbs(stream_id_obj)
        return cls(node_id, stream_id)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsNodeIdPair.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.NodeIdPair import (
            Start,
            AddNodeId,
            AddStreamId,
            End,
        )
        node_id_offset = self.node_id.serialize_to(builder)
        stream_id_offset = None
        if self.stream_id is not None:
            stream_id_offset = self.stream_id.serialize_to(builder)
        
        Start(builder)
        AddNodeId(builder, node_id_offset)
        if stream_id_offset is not None:
            AddStreamId(builder, stream_id_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        node_id = GraphNodeId.make_default()
        stream_id = ObjectId.make_default()
        return cls(node_id, stream_id)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.node_id == other.node_id
        eq = eq and self.stream_id == other.stream_id

        return eq

@dataclass
class NodeList:
    nodes: "List[GraphNode]"

    @classmethod
    def from_fbs(cls, o: FbsNodeList) -> Self:
        nodes = list()
        if not o.NodesIsNone():
            for i in range(o.NodesLength()):
                nodes_val = None
                nodes_obj = o.Nodes(i)
                if nodes_obj is not None:
                    nodes_val = GraphNode.from_fbs(nodes_obj)
                nodes.append(nodes_val)
        return cls(nodes)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsNodeList.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.NodeList import (
            Start,
            AddNodes,
            StartNodesVector,
            End,
        )
        nodes_offsets = list()
        for value in self.nodes:
            nodes_offsets.append(value.serialize_to(builder))
        StartNodesVector(builder, len(self.nodes))
        for i in reversed(range(len(self.nodes))):
            builder.PrependUOffsetTRelative(nodes_offsets[i])
        nodes_offset = builder.EndVector()
        
        Start(builder)
        AddNodes(builder, nodes_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        nodes = []
        return cls(nodes)

    def __eq__(self, other) -> bool:
        eq = True
        if len(self.nodes) != len(other.nodes):
            return False
        for i in range(len(self.nodes)):
            eq = eq and self.nodes[i] == other.nodes[i]

        return eq

@dataclass
class OrderBy:
    field: "str"

    sort: "SortOrder"

    transform: "ValueTransform"

    @classmethod
    def from_fbs(cls, o: FbsOrderBy) -> Self:
        field_str = o.Field()
        assert field_str is not None
        field = field_str.decode('utf-8')
        sort = SortOrder(o.Sort())
        transform = ValueTransform(o.Transform())
        return cls(field, sort, transform)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsOrderBy.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.OrderBy import (
            Start,
            AddField,
            AddSort,
            AddTransform,
            End,
        )
        field_offset = builder.CreateString(self.field)
        
        Start(builder)
        AddField(builder, field_offset)
        AddSort(builder, self.sort.value)
        AddTransform(builder, self.transform.value)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        field = ""
        sort = SortOrder(0)
        transform = ValueTransform(0)
        return cls(field, sort, transform)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.field == other.field
        eq = eq and self.sort == other.sort
        eq = eq and self.transform == other.transform

        return eq

@dataclass
class Projection:
    alias: "str"

    predicate: "Predicate"

    @classmethod
    def from_fbs(cls, o: FbsProjection) -> Self:
        alias_str = o.Alias()
        assert alias_str is not None
        alias = alias_str.decode('utf-8')
        predicate = Predicate(o.Predicate())
        return cls(alias, predicate)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsProjection.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Projection import (
            Start,
            AddAlias,
            AddPredicate,
            End,
        )
        alias_offset = builder.CreateString(self.alias)
        
        Start(builder)
        AddAlias(builder, alias_offset)
        AddPredicate(builder, self.predicate.value)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        alias = ""
        predicate = Predicate(0)
        return cls(alias, predicate)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.alias == other.alias
        eq = eq and self.predicate == other.predicate

        return eq

@dataclass
class QueryPathElement:
    element: "QueryPathElementUnion"

    @classmethod
    def from_fbs(cls, o: FbsQueryPathElement) -> Self:
        element_val = o.Element()
        if element_val is not None:
            element_ty = o.ElementType()
            element = QueryPathElementUnion.from_fbs(element_val, element_ty)
        else:
            raise ValueError("Element is required")
        return cls(element)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsQueryPathElement.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.QueryPathElement import (
            Start,
            AddElement,
            AddElementType,
            End,
        )
        element_offset, element_ty = self.element.serialize_to(builder)
        
        Start(builder)
        AddElement(builder, element_offset)
        AddElementType(builder, element_ty)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        element = QueryPathElementUnion.make_default()
        return cls(element)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.element == other.element

        return eq