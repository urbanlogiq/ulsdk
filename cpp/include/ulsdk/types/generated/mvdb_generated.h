// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_MVDB_H_
#define FLATBUFFERS_GENERATED_MVDB_H_

#include "flatbuffers/flatbuffers.h"

// Ensure the included flatbuffers.h is the same version as when this file was
// generated, otherwise it may not be compatible.
static_assert(FLATBUFFERS_VERSION_MAJOR == 23 &&
              FLATBUFFERS_VERSION_MINOR == 5 &&
              FLATBUFFERS_VERSION_REVISION == 26,
             "Non-compatible flatbuffers version included");

struct LngLat;

struct Attribute;
struct AttributeBuilder;

struct Table;
struct TableBuilder;

enum class TableType : int8_t {
  ObjectStore = 0,
  Geo = 1,
  TimeSeries = 2,
  GeoTimeSeries = 3,
  MIN = ObjectStore,
  MAX = GeoTimeSeries
};

inline const TableType (&EnumValuesTableType())[4] {
  static const TableType values[] = {
    TableType::ObjectStore,
    TableType::Geo,
    TableType::TimeSeries,
    TableType::GeoTimeSeries
  };
  return values;
}

inline const char * const *EnumNamesTableType() {
  static const char * const names[5] = {
    "ObjectStore",
    "Geo",
    "TimeSeries",
    "GeoTimeSeries",
    nullptr
  };
  return names;
}

inline const char *EnumNameTableType(TableType e) {
  if (::flatbuffers::IsOutRange(e, TableType::ObjectStore, TableType::GeoTimeSeries)) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesTableType()[index];
}

FLATBUFFERS_MANUALLY_ALIGNED_STRUCT(4) LngLat FLATBUFFERS_FINAL_CLASS {
 private:
  float lng_;
  float lat_;

 public:
  struct Traits;
  LngLat()
      : lng_(0),
        lat_(0) {
  }
  LngLat(float _lng, float _lat)
      : lng_(::flatbuffers::EndianScalar(_lng)),
        lat_(::flatbuffers::EndianScalar(_lat)) {
  }
  float lng() const {
    return ::flatbuffers::EndianScalar(lng_);
  }
  float lat() const {
    return ::flatbuffers::EndianScalar(lat_);
  }
};
FLATBUFFERS_STRUCT_END(LngLat, 8);

struct LngLat::Traits {
  using type = LngLat;
};

struct Attribute FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef AttributeBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_KEY = 4,
    VT_VALUE = 6
  };
  const ::flatbuffers::String *key() const {
    return GetPointer<const ::flatbuffers::String *>(VT_KEY);
  }
  const ::flatbuffers::String *value() const {
    return GetPointer<const ::flatbuffers::String *>(VT_VALUE);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_KEY) &&
           verifier.VerifyString(key()) &&
           VerifyOffsetRequired(verifier, VT_VALUE) &&
           verifier.VerifyString(value()) &&
           verifier.EndTable();
  }
};

struct AttributeBuilder {
  typedef Attribute Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_key(::flatbuffers::Offset<::flatbuffers::String> key) {
    fbb_.AddOffset(Attribute::VT_KEY, key);
  }
  void add_value(::flatbuffers::Offset<::flatbuffers::String> value) {
    fbb_.AddOffset(Attribute::VT_VALUE, value);
  }
  explicit AttributeBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<Attribute> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<Attribute>(end);
    fbb_.Required(o, Attribute::VT_KEY);
    fbb_.Required(o, Attribute::VT_VALUE);
    return o;
  }
};

inline ::flatbuffers::Offset<Attribute> CreateAttribute(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<::flatbuffers::String> key = 0,
    ::flatbuffers::Offset<::flatbuffers::String> value = 0) {
  AttributeBuilder builder_(_fbb);
  builder_.add_value(value);
  builder_.add_key(key);
  return builder_.Finish();
}

struct Attribute::Traits {
  using type = Attribute;
  static auto constexpr Create = CreateAttribute;
};

inline ::flatbuffers::Offset<Attribute> CreateAttributeDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    const char *key = nullptr,
    const char *value = nullptr) {
  auto key__ = key ? _fbb.CreateString(key) : 0;
  auto value__ = value ? _fbb.CreateString(value) : 0;
  return CreateAttribute(
      _fbb,
      key__,
      value__);
}

struct Table FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef TableBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_NAME = 4,
    VT_SCHEMA = 6,
    VT_TYPE = 8,
    VT_LNGLAT = 12,
    VT_ATTRIBUTES = 14,
    VT_MIN_RES = 16,
    VT_COUNT_THRESHOLD = 18
  };
  const ::flatbuffers::String *name() const {
    return GetPointer<const ::flatbuffers::String *>(VT_NAME);
  }
  const ::flatbuffers::Vector<uint8_t> *schema() const {
    return GetPointer<const ::flatbuffers::Vector<uint8_t> *>(VT_SCHEMA);
  }
  TableType type() const {
    return static_cast<TableType>(GetField<int8_t>(VT_TYPE, 0));
  }
  const LngLat *lnglat() const {
    return GetStruct<const LngLat *>(VT_LNGLAT);
  }
  const ::flatbuffers::Vector<::flatbuffers::Offset<Attribute>> *attributes() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<Attribute>> *>(VT_ATTRIBUTES);
  }
  float min_res() const {
    return GetField<float>(VT_MIN_RES, 0.001f);
  }
  uint32_t count_threshold() const {
    return GetField<uint32_t>(VT_COUNT_THRESHOLD, 0);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_NAME) &&
           verifier.VerifyString(name()) &&
           VerifyOffsetRequired(verifier, VT_SCHEMA) &&
           verifier.VerifyVector(schema()) &&
           VerifyField<int8_t>(verifier, VT_TYPE, 1) &&
           VerifyField<LngLat>(verifier, VT_LNGLAT, 4) &&
           VerifyOffset(verifier, VT_ATTRIBUTES) &&
           verifier.VerifyVector(attributes()) &&
           verifier.VerifyVectorOfTables(attributes()) &&
           VerifyField<float>(verifier, VT_MIN_RES, 4) &&
           VerifyField<uint32_t>(verifier, VT_COUNT_THRESHOLD, 4) &&
           verifier.EndTable();
  }
};

struct TableBuilder {
  typedef Table Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_name(::flatbuffers::Offset<::flatbuffers::String> name) {
    fbb_.AddOffset(Table::VT_NAME, name);
  }
  void add_schema(::flatbuffers::Offset<::flatbuffers::Vector<uint8_t>> schema) {
    fbb_.AddOffset(Table::VT_SCHEMA, schema);
  }
  void add_type(TableType type) {
    fbb_.AddElement<int8_t>(Table::VT_TYPE, static_cast<int8_t>(type), 0);
  }
  void add_lnglat(const LngLat *lnglat) {
    fbb_.AddStruct(Table::VT_LNGLAT, lnglat);
  }
  void add_attributes(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<Attribute>>> attributes) {
    fbb_.AddOffset(Table::VT_ATTRIBUTES, attributes);
  }
  void add_min_res(float min_res) {
    fbb_.AddElement<float>(Table::VT_MIN_RES, min_res, 0.001f);
  }
  void add_count_threshold(uint32_t count_threshold) {
    fbb_.AddElement<uint32_t>(Table::VT_COUNT_THRESHOLD, count_threshold, 0);
  }
  explicit TableBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<Table> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<Table>(end);
    fbb_.Required(o, Table::VT_SCHEMA);
    return o;
  }
};

inline ::flatbuffers::Offset<Table> CreateTable(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<::flatbuffers::String> name = 0,
    ::flatbuffers::Offset<::flatbuffers::Vector<uint8_t>> schema = 0,
    TableType type = TableType::ObjectStore,
    const LngLat *lnglat = nullptr,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<Attribute>>> attributes = 0,
    float min_res = 0.001f,
    uint32_t count_threshold = 0) {
  TableBuilder builder_(_fbb);
  builder_.add_count_threshold(count_threshold);
  builder_.add_min_res(min_res);
  builder_.add_attributes(attributes);
  builder_.add_lnglat(lnglat);
  builder_.add_schema(schema);
  builder_.add_name(name);
  builder_.add_type(type);
  return builder_.Finish();
}

struct Table::Traits {
  using type = Table;
  static auto constexpr Create = CreateTable;
};

inline ::flatbuffers::Offset<Table> CreateTableDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    const char *name = nullptr,
    const std::vector<uint8_t> *schema = nullptr,
    TableType type = TableType::ObjectStore,
    const LngLat *lnglat = nullptr,
    const std::vector<::flatbuffers::Offset<Attribute>> *attributes = nullptr,
    float min_res = 0.001f,
    uint32_t count_threshold = 0) {
  auto name__ = name ? _fbb.CreateString(name) : 0;
  auto schema__ = schema ? _fbb.CreateVector<uint8_t>(*schema) : 0;
  auto attributes__ = attributes ? _fbb.CreateVector<::flatbuffers::Offset<Attribute>>(*attributes) : 0;
  return CreateTable(
      _fbb,
      name__,
      schema__,
      type,
      lnglat,
      attributes__,
      min_res,
      count_threshold);
}

inline const Table *GetTable(const void *buf) {
  return ::flatbuffers::GetRoot<Table>(buf);
}

inline const Table *GetSizePrefixedTable(const void *buf) {
  return ::flatbuffers::GetSizePrefixedRoot<Table>(buf);
}

inline const char *TableIdentifier() {
  return "COLL";
}

inline bool TableBufferHasIdentifier(const void *buf) {
  return ::flatbuffers::BufferHasIdentifier(
      buf, TableIdentifier());
}

inline bool SizePrefixedTableBufferHasIdentifier(const void *buf) {
  return ::flatbuffers::BufferHasIdentifier(
      buf, TableIdentifier(), true);
}

inline bool VerifyTableBuffer(
    ::flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<Table>(TableIdentifier());
}

inline bool VerifySizePrefixedTableBuffer(
    ::flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<Table>(TableIdentifier());
}

inline void FinishTableBuffer(
    ::flatbuffers::FlatBufferBuilder &fbb,
    ::flatbuffers::Offset<Table> root) {
  fbb.Finish(root, TableIdentifier());
}

inline void FinishSizePrefixedTableBuffer(
    ::flatbuffers::FlatBufferBuilder &fbb,
    ::flatbuffers::Offset<Table> root) {
  fbb.FinishSizePrefixed(root, TableIdentifier());
}

#endif  // FLATBUFFERS_GENERATED_MVDB_H_
