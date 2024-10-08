// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_GRAPH_H_
#define FLATBUFFERS_GENERATED_GRAPH_H_

#include "flatbuffers/flatbuffers.h"

// Ensure the included flatbuffers.h is the same version as when this file was
// generated, otherwise it may not be compatible.
static_assert(FLATBUFFERS_VERSION_MAJOR == 23 &&
              FLATBUFFERS_VERSION_MINOR == 5 &&
              FLATBUFFERS_VERSION_REVISION == 26,
             "Non-compatible flatbuffers version included");

#include "api_generated.h"
#include "entity_generated.h"
#include "fun_generated.h"
#include "id_generated.h"

struct Projection;
struct ProjectionBuilder;

struct EdgeQuery;
struct EdgeQueryBuilder;

struct NodeIdPair;
struct NodeIdPairBuilder;

struct Geom;
struct GeomBuilder;

struct GeomOp;
struct GeomOpBuilder;

struct NodeQuery;
struct NodeQueryBuilder;

struct QueryPathElement;
struct QueryPathElementBuilder;

struct OrderBy;
struct OrderByBuilder;

struct GraphQuery;
struct GraphQueryBuilder;

struct NodeList;
struct NodeListBuilder;

struct EdgeList;
struct EdgeListBuilder;

enum class Predicate : int32_t {
  NONE = 0,
  id = 1,
  stream = 2,
  node_id = 3,
  entity_ty = 4,
  node_ty = 5,
  description = 6,
  location = 7,
  geom = 8,
  MIN = NONE,
  MAX = geom
};

inline const Predicate (&EnumValuesPredicate())[9] {
  static const Predicate values[] = {
    Predicate::NONE,
    Predicate::id,
    Predicate::stream,
    Predicate::node_id,
    Predicate::entity_ty,
    Predicate::node_ty,
    Predicate::description,
    Predicate::location,
    Predicate::geom
  };
  return values;
}

inline const char * const *EnumNamesPredicate() {
  static const char * const names[10] = {
    "NONE",
    "id",
    "stream",
    "node_id",
    "entity_ty",
    "node_ty",
    "description",
    "location",
    "geom",
    nullptr
  };
  return names;
}

inline const char *EnumNamePredicate(Predicate e) {
  if (::flatbuffers::IsOutRange(e, Predicate::NONE, Predicate::geom)) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesPredicate()[index];
}

enum class QueryPathElementUnion : uint8_t {
  NONE = 0,
  NodeQuery = 1,
  EdgeQuery = 2,
  MIN = NONE,
  MAX = EdgeQuery
};

inline const QueryPathElementUnion (&EnumValuesQueryPathElementUnion())[3] {
  static const QueryPathElementUnion values[] = {
    QueryPathElementUnion::NONE,
    QueryPathElementUnion::NodeQuery,
    QueryPathElementUnion::EdgeQuery
  };
  return values;
}

inline const char * const *EnumNamesQueryPathElementUnion() {
  static const char * const names[4] = {
    "NONE",
    "NodeQuery",
    "EdgeQuery",
    nullptr
  };
  return names;
}

inline const char *EnumNameQueryPathElementUnion(QueryPathElementUnion e) {
  if (::flatbuffers::IsOutRange(e, QueryPathElementUnion::NONE, QueryPathElementUnion::EdgeQuery)) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesQueryPathElementUnion()[index];
}

template<typename T> struct QueryPathElementUnionTraits {
  static const QueryPathElementUnion enum_value = QueryPathElementUnion::NONE;
};

template<> struct QueryPathElementUnionTraits<NodeQuery> {
  static const QueryPathElementUnion enum_value = QueryPathElementUnion::NodeQuery;
};

template<> struct QueryPathElementUnionTraits<EdgeQuery> {
  static const QueryPathElementUnion enum_value = QueryPathElementUnion::EdgeQuery;
};

bool VerifyQueryPathElementUnion(::flatbuffers::Verifier &verifier, const void *obj, QueryPathElementUnion type);
bool VerifyQueryPathElementUnionVector(::flatbuffers::Verifier &verifier, const ::flatbuffers::Vector<::flatbuffers::Offset<void>> *values, const ::flatbuffers::Vector<QueryPathElementUnion> *types);

enum class ValueTransform : int16_t {
  NONE = 0,
  UuidToBase64 = 1,
  MIN = NONE,
  MAX = UuidToBase64
};

inline const ValueTransform (&EnumValuesValueTransform())[2] {
  static const ValueTransform values[] = {
    ValueTransform::NONE,
    ValueTransform::UuidToBase64
  };
  return values;
}

inline const char * const *EnumNamesValueTransform() {
  static const char * const names[3] = {
    "NONE",
    "UuidToBase64",
    nullptr
  };
  return names;
}

inline const char *EnumNameValueTransform(ValueTransform e) {
  if (::flatbuffers::IsOutRange(e, ValueTransform::NONE, ValueTransform::UuidToBase64)) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesValueTransform()[index];
}

struct Projection FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef ProjectionBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_PREDICATE = 4,
    VT_ALIAS = 6
  };
  Predicate predicate() const {
    return static_cast<Predicate>(GetField<int32_t>(VT_PREDICATE, 0));
  }
  const ::flatbuffers::String *alias() const {
    return GetPointer<const ::flatbuffers::String *>(VT_ALIAS);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<int32_t>(verifier, VT_PREDICATE, 4) &&
           VerifyOffsetRequired(verifier, VT_ALIAS) &&
           verifier.VerifyString(alias()) &&
           verifier.EndTable();
  }
};

struct ProjectionBuilder {
  typedef Projection Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_predicate(Predicate predicate) {
    fbb_.AddElement<int32_t>(Projection::VT_PREDICATE, static_cast<int32_t>(predicate), 0);
  }
  void add_alias(::flatbuffers::Offset<::flatbuffers::String> alias) {
    fbb_.AddOffset(Projection::VT_ALIAS, alias);
  }
  explicit ProjectionBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<Projection> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<Projection>(end);
    fbb_.Required(o, Projection::VT_ALIAS);
    return o;
  }
};

inline ::flatbuffers::Offset<Projection> CreateProjection(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    Predicate predicate = Predicate::NONE,
    ::flatbuffers::Offset<::flatbuffers::String> alias = 0) {
  ProjectionBuilder builder_(_fbb);
  builder_.add_alias(alias);
  builder_.add_predicate(predicate);
  return builder_.Finish();
}

struct Projection::Traits {
  using type = Projection;
  static auto constexpr Create = CreateProjection;
};

inline ::flatbuffers::Offset<Projection> CreateProjectionDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    Predicate predicate = Predicate::NONE,
    const char *alias = nullptr) {
  auto alias__ = alias ? _fbb.CreateString(alias) : 0;
  return CreateProjection(
      _fbb,
      predicate,
      alias__);
}

struct EdgeQuery FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef EdgeQueryBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_EDGE_TY = 4
  };
  EdgeTy edge_ty() const {
    return static_cast<EdgeTy>(GetField<int32_t>(VT_EDGE_TY, 0));
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<int32_t>(verifier, VT_EDGE_TY, 4) &&
           verifier.EndTable();
  }
};

struct EdgeQueryBuilder {
  typedef EdgeQuery Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_edge_ty(EdgeTy edge_ty) {
    fbb_.AddElement<int32_t>(EdgeQuery::VT_EDGE_TY, static_cast<int32_t>(edge_ty), 0);
  }
  explicit EdgeQueryBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<EdgeQuery> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<EdgeQuery>(end);
    return o;
  }
};

inline ::flatbuffers::Offset<EdgeQuery> CreateEdgeQuery(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    EdgeTy edge_ty = EdgeTy::E_INVALID) {
  EdgeQueryBuilder builder_(_fbb);
  builder_.add_edge_ty(edge_ty);
  return builder_.Finish();
}

struct EdgeQuery::Traits {
  using type = EdgeQuery;
  static auto constexpr Create = CreateEdgeQuery;
};

struct NodeIdPair FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef NodeIdPairBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_STREAM_ID = 4,
    VT_NODE_ID = 6
  };
  const ObjectId *stream_id() const {
    return GetPointer<const ObjectId *>(VT_STREAM_ID);
  }
  const GraphNodeId *node_id() const {
    return GetPointer<const GraphNodeId *>(VT_NODE_ID);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_STREAM_ID) &&
           verifier.VerifyTable(stream_id()) &&
           VerifyOffsetRequired(verifier, VT_NODE_ID) &&
           verifier.VerifyTable(node_id()) &&
           verifier.EndTable();
  }
};

struct NodeIdPairBuilder {
  typedef NodeIdPair Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_stream_id(::flatbuffers::Offset<ObjectId> stream_id) {
    fbb_.AddOffset(NodeIdPair::VT_STREAM_ID, stream_id);
  }
  void add_node_id(::flatbuffers::Offset<GraphNodeId> node_id) {
    fbb_.AddOffset(NodeIdPair::VT_NODE_ID, node_id);
  }
  explicit NodeIdPairBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<NodeIdPair> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<NodeIdPair>(end);
    fbb_.Required(o, NodeIdPair::VT_NODE_ID);
    return o;
  }
};

inline ::flatbuffers::Offset<NodeIdPair> CreateNodeIdPair(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<ObjectId> stream_id = 0,
    ::flatbuffers::Offset<GraphNodeId> node_id = 0) {
  NodeIdPairBuilder builder_(_fbb);
  builder_.add_node_id(node_id);
  builder_.add_stream_id(stream_id);
  return builder_.Finish();
}

struct NodeIdPair::Traits {
  using type = NodeIdPair;
  static auto constexpr Create = CreateNodeIdPair;
};

struct Geom FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef GeomBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_GEOM_TYPE = 4,
    VT_GEOM = 6
  };
  Geometry geom_type() const {
    return static_cast<Geometry>(GetField<uint8_t>(VT_GEOM_TYPE, 0));
  }
  const void *geom() const {
    return GetPointer<const void *>(VT_GEOM);
  }
  template<typename T> const T *geom_as() const;
  const Point *geom_as_Point() const {
    return geom_type() == Geometry::Point ? static_cast<const Point *>(geom()) : nullptr;
  }
  const Line *geom_as_Line() const {
    return geom_type() == Geometry::Line ? static_cast<const Line *>(geom()) : nullptr;
  }
  const MultiLine *geom_as_MultiLine() const {
    return geom_type() == Geometry::MultiLine ? static_cast<const MultiLine *>(geom()) : nullptr;
  }
  const Polygon *geom_as_Polygon() const {
    return geom_type() == Geometry::Polygon ? static_cast<const Polygon *>(geom()) : nullptr;
  }
  const MultiPolygon *geom_as_MultiPolygon() const {
    return geom_type() == Geometry::MultiPolygon ? static_cast<const MultiPolygon *>(geom()) : nullptr;
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<uint8_t>(verifier, VT_GEOM_TYPE, 1) &&
           VerifyOffsetRequired(verifier, VT_GEOM) &&
           VerifyGeometry(verifier, geom(), geom_type()) &&
           verifier.EndTable();
  }
};

template<> inline const Point *Geom::geom_as<Point>() const {
  return geom_as_Point();
}

template<> inline const Line *Geom::geom_as<Line>() const {
  return geom_as_Line();
}

template<> inline const MultiLine *Geom::geom_as<MultiLine>() const {
  return geom_as_MultiLine();
}

template<> inline const Polygon *Geom::geom_as<Polygon>() const {
  return geom_as_Polygon();
}

template<> inline const MultiPolygon *Geom::geom_as<MultiPolygon>() const {
  return geom_as_MultiPolygon();
}

struct GeomBuilder {
  typedef Geom Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_geom_type(Geometry geom_type) {
    fbb_.AddElement<uint8_t>(Geom::VT_GEOM_TYPE, static_cast<uint8_t>(geom_type), 0);
  }
  void add_geom(::flatbuffers::Offset<void> geom) {
    fbb_.AddOffset(Geom::VT_GEOM, geom);
  }
  explicit GeomBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<Geom> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<Geom>(end);
    fbb_.Required(o, Geom::VT_GEOM);
    return o;
  }
};

inline ::flatbuffers::Offset<Geom> CreateGeom(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    Geometry geom_type = Geometry::NONE,
    ::flatbuffers::Offset<void> geom = 0) {
  GeomBuilder builder_(_fbb);
  builder_.add_geom(geom);
  builder_.add_geom_type(geom_type);
  return builder_.Finish();
}

struct Geom::Traits {
  using type = Geom;
  static auto constexpr Create = CreateGeom;
};

struct GeomOp FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef GeomOpBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_OP = 4,
    VT_GEOMS = 6,
    VT_PREDICATE = 8
  };
  Fn op() const {
    return static_cast<Fn>(GetField<int16_t>(VT_OP, 0));
  }
  const ::flatbuffers::Vector<::flatbuffers::Offset<Geom>> *geoms() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<Geom>> *>(VT_GEOMS);
  }
  Predicate predicate() const {
    return static_cast<Predicate>(GetField<int32_t>(VT_PREDICATE, 7));
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<int16_t>(verifier, VT_OP, 2) &&
           VerifyOffsetRequired(verifier, VT_GEOMS) &&
           verifier.VerifyVector(geoms()) &&
           verifier.VerifyVectorOfTables(geoms()) &&
           VerifyField<int32_t>(verifier, VT_PREDICATE, 4) &&
           verifier.EndTable();
  }
};

struct GeomOpBuilder {
  typedef GeomOp Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_op(Fn op) {
    fbb_.AddElement<int16_t>(GeomOp::VT_OP, static_cast<int16_t>(op), 0);
  }
  void add_geoms(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<Geom>>> geoms) {
    fbb_.AddOffset(GeomOp::VT_GEOMS, geoms);
  }
  void add_predicate(Predicate predicate) {
    fbb_.AddElement<int32_t>(GeomOp::VT_PREDICATE, static_cast<int32_t>(predicate), 7);
  }
  explicit GeomOpBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<GeomOp> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<GeomOp>(end);
    fbb_.Required(o, GeomOp::VT_GEOMS);
    return o;
  }
};

inline ::flatbuffers::Offset<GeomOp> CreateGeomOp(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    Fn op = Fn::None,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<Geom>>> geoms = 0,
    Predicate predicate = Predicate::location) {
  GeomOpBuilder builder_(_fbb);
  builder_.add_predicate(predicate);
  builder_.add_geoms(geoms);
  builder_.add_op(op);
  return builder_.Finish();
}

struct GeomOp::Traits {
  using type = GeomOp;
  static auto constexpr Create = CreateGeomOp;
};

inline ::flatbuffers::Offset<GeomOp> CreateGeomOpDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    Fn op = Fn::None,
    const std::vector<::flatbuffers::Offset<Geom>> *geoms = nullptr,
    Predicate predicate = Predicate::location) {
  auto geoms__ = geoms ? _fbb.CreateVector<::flatbuffers::Offset<Geom>>(*geoms) : 0;
  return CreateGeomOp(
      _fbb,
      op,
      geoms__,
      predicate);
}

struct NodeQuery FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef NodeQueryBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_STREAM_IDS = 4,
    VT_ENTITY_TYS = 6,
    VT_DESCRIPTIONS = 8,
    VT_NODE_IDS = 10,
    VT_PROJECTIONS = 12,
    VT_GEOM_OP = 14
  };
  const ::flatbuffers::Vector<::flatbuffers::Offset<ObjectId>> *stream_ids() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<ObjectId>> *>(VT_STREAM_IDS);
  }
  const ::flatbuffers::Vector<EntityTy> *entity_tys() const {
    return GetPointer<const ::flatbuffers::Vector<EntityTy> *>(VT_ENTITY_TYS);
  }
  /// If descriptions are provided here, then results will be ordered by their string similarity to the
  /// descriptions here. This ordering is secondary to the any top-level order_by that might be provided.
  const ::flatbuffers::Vector<::flatbuffers::Offset<::flatbuffers::String>> *descriptions() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<::flatbuffers::String>> *>(VT_DESCRIPTIONS);
  }
  const ::flatbuffers::Vector<::flatbuffers::Offset<NodeIdPair>> *node_ids() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<NodeIdPair>> *>(VT_NODE_IDS);
  }
  const ::flatbuffers::Vector<::flatbuffers::Offset<Projection>> *projections() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<Projection>> *>(VT_PROJECTIONS);
  }
  const GeomOp *geom_op() const {
    return GetPointer<const GeomOp *>(VT_GEOM_OP);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_STREAM_IDS) &&
           verifier.VerifyVector(stream_ids()) &&
           verifier.VerifyVectorOfTables(stream_ids()) &&
           VerifyOffset(verifier, VT_ENTITY_TYS) &&
           verifier.VerifyVector(entity_tys()) &&
           VerifyOffset(verifier, VT_DESCRIPTIONS) &&
           verifier.VerifyVector(descriptions()) &&
           verifier.VerifyVectorOfStrings(descriptions()) &&
           VerifyOffset(verifier, VT_NODE_IDS) &&
           verifier.VerifyVector(node_ids()) &&
           verifier.VerifyVectorOfTables(node_ids()) &&
           VerifyOffset(verifier, VT_PROJECTIONS) &&
           verifier.VerifyVector(projections()) &&
           verifier.VerifyVectorOfTables(projections()) &&
           VerifyOffset(verifier, VT_GEOM_OP) &&
           verifier.VerifyTable(geom_op()) &&
           verifier.EndTable();
  }
};

struct NodeQueryBuilder {
  typedef NodeQuery Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_stream_ids(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<ObjectId>>> stream_ids) {
    fbb_.AddOffset(NodeQuery::VT_STREAM_IDS, stream_ids);
  }
  void add_entity_tys(::flatbuffers::Offset<::flatbuffers::Vector<EntityTy>> entity_tys) {
    fbb_.AddOffset(NodeQuery::VT_ENTITY_TYS, entity_tys);
  }
  void add_descriptions(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<::flatbuffers::String>>> descriptions) {
    fbb_.AddOffset(NodeQuery::VT_DESCRIPTIONS, descriptions);
  }
  void add_node_ids(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<NodeIdPair>>> node_ids) {
    fbb_.AddOffset(NodeQuery::VT_NODE_IDS, node_ids);
  }
  void add_projections(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<Projection>>> projections) {
    fbb_.AddOffset(NodeQuery::VT_PROJECTIONS, projections);
  }
  void add_geom_op(::flatbuffers::Offset<GeomOp> geom_op) {
    fbb_.AddOffset(NodeQuery::VT_GEOM_OP, geom_op);
  }
  explicit NodeQueryBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<NodeQuery> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<NodeQuery>(end);
    return o;
  }
};

inline ::flatbuffers::Offset<NodeQuery> CreateNodeQuery(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<ObjectId>>> stream_ids = 0,
    ::flatbuffers::Offset<::flatbuffers::Vector<EntityTy>> entity_tys = 0,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<::flatbuffers::String>>> descriptions = 0,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<NodeIdPair>>> node_ids = 0,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<Projection>>> projections = 0,
    ::flatbuffers::Offset<GeomOp> geom_op = 0) {
  NodeQueryBuilder builder_(_fbb);
  builder_.add_geom_op(geom_op);
  builder_.add_projections(projections);
  builder_.add_node_ids(node_ids);
  builder_.add_descriptions(descriptions);
  builder_.add_entity_tys(entity_tys);
  builder_.add_stream_ids(stream_ids);
  return builder_.Finish();
}

struct NodeQuery::Traits {
  using type = NodeQuery;
  static auto constexpr Create = CreateNodeQuery;
};

inline ::flatbuffers::Offset<NodeQuery> CreateNodeQueryDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<::flatbuffers::Offset<ObjectId>> *stream_ids = nullptr,
    const std::vector<EntityTy> *entity_tys = nullptr,
    const std::vector<::flatbuffers::Offset<::flatbuffers::String>> *descriptions = nullptr,
    const std::vector<::flatbuffers::Offset<NodeIdPair>> *node_ids = nullptr,
    const std::vector<::flatbuffers::Offset<Projection>> *projections = nullptr,
    ::flatbuffers::Offset<GeomOp> geom_op = 0) {
  auto stream_ids__ = stream_ids ? _fbb.CreateVector<::flatbuffers::Offset<ObjectId>>(*stream_ids) : 0;
  auto entity_tys__ = entity_tys ? _fbb.CreateVector<EntityTy>(*entity_tys) : 0;
  auto descriptions__ = descriptions ? _fbb.CreateVector<::flatbuffers::Offset<::flatbuffers::String>>(*descriptions) : 0;
  auto node_ids__ = node_ids ? _fbb.CreateVector<::flatbuffers::Offset<NodeIdPair>>(*node_ids) : 0;
  auto projections__ = projections ? _fbb.CreateVector<::flatbuffers::Offset<Projection>>(*projections) : 0;
  return CreateNodeQuery(
      _fbb,
      stream_ids__,
      entity_tys__,
      descriptions__,
      node_ids__,
      projections__,
      geom_op);
}

struct QueryPathElement FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef QueryPathElementBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_ELEMENT_TYPE = 4,
    VT_ELEMENT = 6
  };
  QueryPathElementUnion element_type() const {
    return static_cast<QueryPathElementUnion>(GetField<uint8_t>(VT_ELEMENT_TYPE, 0));
  }
  const void *element() const {
    return GetPointer<const void *>(VT_ELEMENT);
  }
  template<typename T> const T *element_as() const;
  const NodeQuery *element_as_NodeQuery() const {
    return element_type() == QueryPathElementUnion::NodeQuery ? static_cast<const NodeQuery *>(element()) : nullptr;
  }
  const EdgeQuery *element_as_EdgeQuery() const {
    return element_type() == QueryPathElementUnion::EdgeQuery ? static_cast<const EdgeQuery *>(element()) : nullptr;
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<uint8_t>(verifier, VT_ELEMENT_TYPE, 1) &&
           VerifyOffsetRequired(verifier, VT_ELEMENT) &&
           VerifyQueryPathElementUnion(verifier, element(), element_type()) &&
           verifier.EndTable();
  }
};

template<> inline const NodeQuery *QueryPathElement::element_as<NodeQuery>() const {
  return element_as_NodeQuery();
}

template<> inline const EdgeQuery *QueryPathElement::element_as<EdgeQuery>() const {
  return element_as_EdgeQuery();
}

struct QueryPathElementBuilder {
  typedef QueryPathElement Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_element_type(QueryPathElementUnion element_type) {
    fbb_.AddElement<uint8_t>(QueryPathElement::VT_ELEMENT_TYPE, static_cast<uint8_t>(element_type), 0);
  }
  void add_element(::flatbuffers::Offset<void> element) {
    fbb_.AddOffset(QueryPathElement::VT_ELEMENT, element);
  }
  explicit QueryPathElementBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<QueryPathElement> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<QueryPathElement>(end);
    fbb_.Required(o, QueryPathElement::VT_ELEMENT);
    return o;
  }
};

inline ::flatbuffers::Offset<QueryPathElement> CreateQueryPathElement(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    QueryPathElementUnion element_type = QueryPathElementUnion::NONE,
    ::flatbuffers::Offset<void> element = 0) {
  QueryPathElementBuilder builder_(_fbb);
  builder_.add_element(element);
  builder_.add_element_type(element_type);
  return builder_.Finish();
}

struct QueryPathElement::Traits {
  using type = QueryPathElement;
  static auto constexpr Create = CreateQueryPathElement;
};

struct OrderBy FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef OrderByBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_SORT = 4,
    VT_FIELD = 6,
    VT_TRANSFORM = 8
  };
  SortOrder sort() const {
    return static_cast<SortOrder>(GetField<uint32_t>(VT_SORT, 0));
  }
  const ::flatbuffers::String *field() const {
    return GetPointer<const ::flatbuffers::String *>(VT_FIELD);
  }
  ValueTransform transform() const {
    return static_cast<ValueTransform>(GetField<int16_t>(VT_TRANSFORM, 0));
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<uint32_t>(verifier, VT_SORT, 4) &&
           VerifyOffsetRequired(verifier, VT_FIELD) &&
           verifier.VerifyString(field()) &&
           VerifyField<int16_t>(verifier, VT_TRANSFORM, 2) &&
           verifier.EndTable();
  }
};

struct OrderByBuilder {
  typedef OrderBy Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_sort(SortOrder sort) {
    fbb_.AddElement<uint32_t>(OrderBy::VT_SORT, static_cast<uint32_t>(sort), 0);
  }
  void add_field(::flatbuffers::Offset<::flatbuffers::String> field) {
    fbb_.AddOffset(OrderBy::VT_FIELD, field);
  }
  void add_transform(ValueTransform transform) {
    fbb_.AddElement<int16_t>(OrderBy::VT_TRANSFORM, static_cast<int16_t>(transform), 0);
  }
  explicit OrderByBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<OrderBy> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<OrderBy>(end);
    fbb_.Required(o, OrderBy::VT_FIELD);
    return o;
  }
};

inline ::flatbuffers::Offset<OrderBy> CreateOrderBy(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    SortOrder sort = SortOrder::ASC,
    ::flatbuffers::Offset<::flatbuffers::String> field = 0,
    ValueTransform transform = ValueTransform::NONE) {
  OrderByBuilder builder_(_fbb);
  builder_.add_field(field);
  builder_.add_sort(sort);
  builder_.add_transform(transform);
  return builder_.Finish();
}

struct OrderBy::Traits {
  using type = OrderBy;
  static auto constexpr Create = CreateOrderBy;
};

inline ::flatbuffers::Offset<OrderBy> CreateOrderByDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    SortOrder sort = SortOrder::ASC,
    const char *field = nullptr,
    ValueTransform transform = ValueTransform::NONE) {
  auto field__ = field ? _fbb.CreateString(field) : 0;
  return CreateOrderBy(
      _fbb,
      sort,
      field__,
      transform);
}

/// The GraphQuery encapsulates the entire world graph query.
struct GraphQuery FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef GraphQueryBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_PATH = 4,
    VT_LIMIT = 6,
    VT_ORDER_BY = 8
  };
  const ::flatbuffers::Vector<::flatbuffers::Offset<QueryPathElement>> *path() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<QueryPathElement>> *>(VT_PATH);
  }
  uint32_t limit() const {
    return GetField<uint32_t>(VT_LIMIT, 0);
  }
  const ::flatbuffers::Vector<::flatbuffers::Offset<OrderBy>> *order_by() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<OrderBy>> *>(VT_ORDER_BY);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_PATH) &&
           verifier.VerifyVector(path()) &&
           verifier.VerifyVectorOfTables(path()) &&
           VerifyField<uint32_t>(verifier, VT_LIMIT, 4) &&
           VerifyOffset(verifier, VT_ORDER_BY) &&
           verifier.VerifyVector(order_by()) &&
           verifier.VerifyVectorOfTables(order_by()) &&
           verifier.EndTable();
  }
};

struct GraphQueryBuilder {
  typedef GraphQuery Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_path(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<QueryPathElement>>> path) {
    fbb_.AddOffset(GraphQuery::VT_PATH, path);
  }
  void add_limit(uint32_t limit) {
    fbb_.AddElement<uint32_t>(GraphQuery::VT_LIMIT, limit, 0);
  }
  void add_order_by(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<OrderBy>>> order_by) {
    fbb_.AddOffset(GraphQuery::VT_ORDER_BY, order_by);
  }
  explicit GraphQueryBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<GraphQuery> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<GraphQuery>(end);
    fbb_.Required(o, GraphQuery::VT_PATH);
    return o;
  }
};

inline ::flatbuffers::Offset<GraphQuery> CreateGraphQuery(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<QueryPathElement>>> path = 0,
    uint32_t limit = 0,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<OrderBy>>> order_by = 0) {
  GraphQueryBuilder builder_(_fbb);
  builder_.add_order_by(order_by);
  builder_.add_limit(limit);
  builder_.add_path(path);
  return builder_.Finish();
}

struct GraphQuery::Traits {
  using type = GraphQuery;
  static auto constexpr Create = CreateGraphQuery;
};

inline ::flatbuffers::Offset<GraphQuery> CreateGraphQueryDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<::flatbuffers::Offset<QueryPathElement>> *path = nullptr,
    uint32_t limit = 0,
    const std::vector<::flatbuffers::Offset<OrderBy>> *order_by = nullptr) {
  auto path__ = path ? _fbb.CreateVector<::flatbuffers::Offset<QueryPathElement>>(*path) : 0;
  auto order_by__ = order_by ? _fbb.CreateVector<::flatbuffers::Offset<OrderBy>>(*order_by) : 0;
  return CreateGraphQuery(
      _fbb,
      path__,
      limit,
      order_by__);
}

struct NodeList FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef NodeListBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_NODES = 4
  };
  const ::flatbuffers::Vector<::flatbuffers::Offset<GraphNode>> *nodes() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<GraphNode>> *>(VT_NODES);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_NODES) &&
           verifier.VerifyVector(nodes()) &&
           verifier.VerifyVectorOfTables(nodes()) &&
           verifier.EndTable();
  }
};

struct NodeListBuilder {
  typedef NodeList Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_nodes(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<GraphNode>>> nodes) {
    fbb_.AddOffset(NodeList::VT_NODES, nodes);
  }
  explicit NodeListBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<NodeList> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<NodeList>(end);
    fbb_.Required(o, NodeList::VT_NODES);
    return o;
  }
};

inline ::flatbuffers::Offset<NodeList> CreateNodeList(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<GraphNode>>> nodes = 0) {
  NodeListBuilder builder_(_fbb);
  builder_.add_nodes(nodes);
  return builder_.Finish();
}

struct NodeList::Traits {
  using type = NodeList;
  static auto constexpr Create = CreateNodeList;
};

inline ::flatbuffers::Offset<NodeList> CreateNodeListDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<::flatbuffers::Offset<GraphNode>> *nodes = nullptr) {
  auto nodes__ = nodes ? _fbb.CreateVector<::flatbuffers::Offset<GraphNode>>(*nodes) : 0;
  return CreateNodeList(
      _fbb,
      nodes__);
}

struct EdgeList FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef EdgeListBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_EDGES = 4
  };
  const ::flatbuffers::Vector<::flatbuffers::Offset<GraphEdge>> *edges() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<GraphEdge>> *>(VT_EDGES);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_EDGES) &&
           verifier.VerifyVector(edges()) &&
           verifier.VerifyVectorOfTables(edges()) &&
           verifier.EndTable();
  }
};

struct EdgeListBuilder {
  typedef EdgeList Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_edges(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<GraphEdge>>> edges) {
    fbb_.AddOffset(EdgeList::VT_EDGES, edges);
  }
  explicit EdgeListBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<EdgeList> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<EdgeList>(end);
    fbb_.Required(o, EdgeList::VT_EDGES);
    return o;
  }
};

inline ::flatbuffers::Offset<EdgeList> CreateEdgeList(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<GraphEdge>>> edges = 0) {
  EdgeListBuilder builder_(_fbb);
  builder_.add_edges(edges);
  return builder_.Finish();
}

struct EdgeList::Traits {
  using type = EdgeList;
  static auto constexpr Create = CreateEdgeList;
};

inline ::flatbuffers::Offset<EdgeList> CreateEdgeListDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<::flatbuffers::Offset<GraphEdge>> *edges = nullptr) {
  auto edges__ = edges ? _fbb.CreateVector<::flatbuffers::Offset<GraphEdge>>(*edges) : 0;
  return CreateEdgeList(
      _fbb,
      edges__);
}

inline bool VerifyQueryPathElementUnion(::flatbuffers::Verifier &verifier, const void *obj, QueryPathElementUnion type) {
  switch (type) {
    case QueryPathElementUnion::NONE: {
      return true;
    }
    case QueryPathElementUnion::NodeQuery: {
      auto ptr = reinterpret_cast<const NodeQuery *>(obj);
      return verifier.VerifyTable(ptr);
    }
    case QueryPathElementUnion::EdgeQuery: {
      auto ptr = reinterpret_cast<const EdgeQuery *>(obj);
      return verifier.VerifyTable(ptr);
    }
    default: return true;
  }
}

inline bool VerifyQueryPathElementUnionVector(::flatbuffers::Verifier &verifier, const ::flatbuffers::Vector<::flatbuffers::Offset<void>> *values, const ::flatbuffers::Vector<QueryPathElementUnion> *types) {
  if (!values || !types) return !values && !types;
  if (values->size() != types->size()) return false;
  for (::flatbuffers::uoffset_t i = 0; i < values->size(); ++i) {
    if (!VerifyQueryPathElementUnion(
        verifier,  values->Get(i), types->GetEnum<QueryPathElementUnion>(i))) {
      return false;
    }
  }
  return true;
}

#endif  // FLATBUFFERS_GENERATED_GRAPH_H_
