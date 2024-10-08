// Copyright (c), CommunityLogiq Software
// 
// THIS FILE IS AUTOGENERATED, DO NOT EDIT

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <variant>
#include <vector>

#include "flatbuffers/flatbuffers.h"
#include "ulsdk/types/api.h"
#include "ulsdk/types/entity.h"
#include "ulsdk/types/fun.h"
#include "ulsdk/types/id.h"
#include "ulsdk/types/generated/graph_generated.h"

namespace ul {
namespace types {

struct EdgeList;
struct EdgeQuery;
struct Geom;
struct GeomOp;
struct GraphQuery;
struct NodeIdPair;
struct NodeList;
struct NodeQuery;
struct OrderBy;
struct Projection;
struct QueryPathElement;

using ::Predicate;
typedef std::variant<
    std::shared_ptr<NodeQuery>,
    std::shared_ptr<EdgeQuery>
> QueryPathElementUnion;

using ::ValueTransform;
struct GeomOp {
    std::vector<Geom> geoms_;
    Fn op_;
    Predicate predicate_;

    GeomOp();
    GeomOp(const ::GeomOp *root);
    GeomOp(const std::vector<uint8_t> &bytes);
};

struct NodeQuery {
    std::optional<std::vector<std::string>> descriptions_;
    std::optional<std::vector<EntityTy>> entity_tys_;
    std::optional<GeomOp> geom_op_;
    std::optional<std::vector<NodeIdPair>> node_ids_;
    std::optional<std::vector<Projection>> projections_;
    std::optional<std::vector<ObjectId>> stream_ids_;

    NodeQuery();
    NodeQuery(const ::NodeQuery *root);
    NodeQuery(const std::vector<uint8_t> &bytes);
};

struct EdgeQuery {
    EdgeTy edge_ty_;

    EdgeQuery();
    EdgeQuery(const ::EdgeQuery *root);
    EdgeQuery(const std::vector<uint8_t> &bytes);
};

struct EdgeList {
    std::vector<GraphEdge> edges_;

    EdgeList();
    EdgeList(const ::EdgeList *root);
    EdgeList(const std::vector<uint8_t> &bytes);
};

struct Geom {
    Geometry geom_;

    Geom();
    Geom(const ::Geom *root);
    Geom(const std::vector<uint8_t> &bytes);
};

///
/// The GraphQuery encapsulates the entire world graph query.
///
struct GraphQuery {
    uint32_t limit_;
    std::optional<std::vector<OrderBy>> order_by_;
    std::vector<QueryPathElement> path_;

    GraphQuery();
    GraphQuery(const ::GraphQuery *root);
    GraphQuery(const std::vector<uint8_t> &bytes);
};

struct NodeIdPair {
    GraphNodeId node_id_;
    std::optional<ObjectId> stream_id_;

    NodeIdPair();
    NodeIdPair(const ::NodeIdPair *root);
    NodeIdPair(const std::vector<uint8_t> &bytes);
};

struct NodeList {
    std::vector<GraphNode> nodes_;

    NodeList();
    NodeList(const ::NodeList *root);
    NodeList(const std::vector<uint8_t> &bytes);
};

struct OrderBy {
    std::string field_;
    SortOrder sort_;
    ValueTransform transform_;

    OrderBy();
    OrderBy(const ::OrderBy *root);
    OrderBy(const std::vector<uint8_t> &bytes);
};

struct Projection {
    std::string alias_;
    Predicate predicate_;

    Projection();
    Projection(const ::Projection *root);
    Projection(const std::vector<uint8_t> &bytes);
};

struct QueryPathElement {
    QueryPathElementUnion element_;

    QueryPathElement();
    QueryPathElement(const ::QueryPathElement *root);
    QueryPathElement(const std::vector<uint8_t> &bytes);
};

std::pair<::flatbuffers::Offset<void>, ::QueryPathElementUnion>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const QueryPathElementUnion &o);
::flatbuffers::Offset<::GeomOp>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const GeomOp &);

::flatbuffers::Offset<::NodeQuery>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const NodeQuery &);

::flatbuffers::Offset<::EdgeQuery>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const EdgeQuery &);

::flatbuffers::Offset<::EdgeList>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const EdgeList &);

::flatbuffers::Offset<::Geom>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Geom &);

::flatbuffers::Offset<::GraphQuery>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const GraphQuery &);

::flatbuffers::Offset<::NodeIdPair>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const NodeIdPair &);

::flatbuffers::Offset<::NodeList>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const NodeList &);

::flatbuffers::Offset<::OrderBy>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const OrderBy &);

::flatbuffers::Offset<::Projection>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Projection &);

::flatbuffers::Offset<::QueryPathElement>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const QueryPathElement &);


std::vector<uint8_t>
to_bytes(const GeomOp &o);

std::vector<uint8_t>
to_bytes(const NodeQuery &o);

std::vector<uint8_t>
to_bytes(const EdgeQuery &o);

std::vector<uint8_t>
to_bytes(const EdgeList &o);

std::vector<uint8_t>
to_bytes(const Geom &o);

std::vector<uint8_t>
to_bytes(const GraphQuery &o);

std::vector<uint8_t>
to_bytes(const NodeIdPair &o);

std::vector<uint8_t>
to_bytes(const NodeList &o);

std::vector<uint8_t>
to_bytes(const OrderBy &o);

std::vector<uint8_t>
to_bytes(const Projection &o);

std::vector<uint8_t>
to_bytes(const QueryPathElement &o);


} // namespace types
} // namespace ul
