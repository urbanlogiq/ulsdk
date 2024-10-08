// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_TABLE_H_
#define FLATBUFFERS_GENERATED_TABLE_H_

#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/flexbuffers.h"
#include "flatbuffers/flex_flat_util.h"

// Ensure the included flatbuffers.h is the same version as when this file was
// generated, otherwise it may not be compatible.
static_assert(FLATBUFFERS_VERSION_MAJOR == 23 &&
              FLATBUFFERS_VERSION_MINOR == 5 &&
              FLATBUFFERS_VERSION_REVISION == 26,
             "Non-compatible flatbuffers version included");

#include "Schema_generated.h"
#include "fs_generated.h"
#include "id_generated.h"
#include "query_generated.h"
#include "value_generated.h"

struct Set;
struct SetBuilder;

struct RmRow;
struct RmRowBuilder;

struct RestoreRow;
struct RestoreRowBuilder;

struct OpEntry;
struct OpEntryBuilder;

struct DiffStream;
struct DiffStreamBuilder;

struct NewTable;
struct NewTableBuilder;

struct Modify;
struct ModifyBuilder;

struct Delete;
struct DeleteBuilder;

struct Restore;
struct RestoreBuilder;

struct ChangeOpEntry;
struct ChangeOpEntryBuilder;

struct ChangeSet;
struct ChangeSetBuilder;

struct History;
struct HistoryBuilder;

/// Table Ops are used to modify the contents of a table.
enum class Op : uint8_t {
  NONE = 0,
  Set = 1,
  RmRow = 2,
  RestoreRow = 3,
  MIN = NONE,
  MAX = RestoreRow
};

inline const Op (&EnumValuesOp())[4] {
  static const Op values[] = {
    Op::NONE,
    Op::Set,
    Op::RmRow,
    Op::RestoreRow
  };
  return values;
}

inline const char * const *EnumNamesOp() {
  static const char * const names[5] = {
    "NONE",
    "Set",
    "RmRow",
    "RestoreRow",
    nullptr
  };
  return names;
}

inline const char *EnumNameOp(Op e) {
  if (::flatbuffers::IsOutRange(e, Op::NONE, Op::RestoreRow)) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesOp()[index];
}

template<typename T> struct OpTraits {
  static const Op enum_value = Op::NONE;
};

template<> struct OpTraits<Set> {
  static const Op enum_value = Op::Set;
};

template<> struct OpTraits<RmRow> {
  static const Op enum_value = Op::RmRow;
};

template<> struct OpTraits<RestoreRow> {
  static const Op enum_value = Op::RestoreRow;
};

bool VerifyOp(::flatbuffers::Verifier &verifier, const void *obj, Op type);
bool VerifyOpVector(::flatbuffers::Verifier &verifier, const ::flatbuffers::Vector<::flatbuffers::Offset<void>> *values, const ::flatbuffers::Vector<Op> *types);

enum class ChangeOp : uint8_t {
  NONE = 0,
  Modify = 1,
  Delete = 2,
  Restore = 3,
  MIN = NONE,
  MAX = Restore
};

inline const ChangeOp (&EnumValuesChangeOp())[4] {
  static const ChangeOp values[] = {
    ChangeOp::NONE,
    ChangeOp::Modify,
    ChangeOp::Delete,
    ChangeOp::Restore
  };
  return values;
}

inline const char * const *EnumNamesChangeOp() {
  static const char * const names[5] = {
    "NONE",
    "Modify",
    "Delete",
    "Restore",
    nullptr
  };
  return names;
}

inline const char *EnumNameChangeOp(ChangeOp e) {
  if (::flatbuffers::IsOutRange(e, ChangeOp::NONE, ChangeOp::Restore)) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesChangeOp()[index];
}

template<typename T> struct ChangeOpTraits {
  static const ChangeOp enum_value = ChangeOp::NONE;
};

template<> struct ChangeOpTraits<Modify> {
  static const ChangeOp enum_value = ChangeOp::Modify;
};

template<> struct ChangeOpTraits<Delete> {
  static const ChangeOp enum_value = ChangeOp::Delete;
};

template<> struct ChangeOpTraits<Restore> {
  static const ChangeOp enum_value = ChangeOp::Restore;
};

bool VerifyChangeOp(::flatbuffers::Verifier &verifier, const void *obj, ChangeOp type);
bool VerifyChangeOpVector(::flatbuffers::Verifier &verifier, const ::flatbuffers::Vector<::flatbuffers::Offset<void>> *values, const ::flatbuffers::Vector<ChangeOp> *types);

/// The Set operation is used to set the value of a cell in a table.
struct Set FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef SetBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_ROW = 4,
    VT_COL = 6,
    VT_VALUE = 8
  };
  /// The value of the ul_node_id column, which uniquely identifies the row.
  const GenericId *row() const {
    return GetPointer<const GenericId *>(VT_ROW);
  }
  /// Name of the column to set.
  const ::flatbuffers::String *col() const {
    return GetPointer<const ::flatbuffers::String *>(VT_COL);
  }
  /// The value to set.
  const ValueInstance *value() const {
    return GetPointer<const ValueInstance *>(VT_VALUE);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_ROW) &&
           verifier.VerifyTable(row()) &&
           VerifyOffsetRequired(verifier, VT_COL) &&
           verifier.VerifyString(col()) &&
           VerifyOffsetRequired(verifier, VT_VALUE) &&
           verifier.VerifyTable(value()) &&
           verifier.EndTable();
  }
};

struct SetBuilder {
  typedef Set Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_row(::flatbuffers::Offset<GenericId> row) {
    fbb_.AddOffset(Set::VT_ROW, row);
  }
  void add_col(::flatbuffers::Offset<::flatbuffers::String> col) {
    fbb_.AddOffset(Set::VT_COL, col);
  }
  void add_value(::flatbuffers::Offset<ValueInstance> value) {
    fbb_.AddOffset(Set::VT_VALUE, value);
  }
  explicit SetBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<Set> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<Set>(end);
    fbb_.Required(o, Set::VT_ROW);
    fbb_.Required(o, Set::VT_COL);
    fbb_.Required(o, Set::VT_VALUE);
    return o;
  }
};

inline ::flatbuffers::Offset<Set> CreateSet(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<GenericId> row = 0,
    ::flatbuffers::Offset<::flatbuffers::String> col = 0,
    ::flatbuffers::Offset<ValueInstance> value = 0) {
  SetBuilder builder_(_fbb);
  builder_.add_value(value);
  builder_.add_col(col);
  builder_.add_row(row);
  return builder_.Finish();
}

struct Set::Traits {
  using type = Set;
  static auto constexpr Create = CreateSet;
};

inline ::flatbuffers::Offset<Set> CreateSetDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<GenericId> row = 0,
    const char *col = nullptr,
    ::flatbuffers::Offset<ValueInstance> value = 0) {
  auto col__ = col ? _fbb.CreateString(col) : 0;
  return CreateSet(
      _fbb,
      row,
      col__,
      value);
}

/// The RmRow operation is used to remove a row from a table.
struct RmRow FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef RmRowBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_ROW = 4
  };
  /// The value of the ul_node_id column, which uniquely identifies the row.
  const GenericId *row() const {
    return GetPointer<const GenericId *>(VT_ROW);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_ROW) &&
           verifier.VerifyTable(row()) &&
           verifier.EndTable();
  }
};

struct RmRowBuilder {
  typedef RmRow Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_row(::flatbuffers::Offset<GenericId> row) {
    fbb_.AddOffset(RmRow::VT_ROW, row);
  }
  explicit RmRowBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<RmRow> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<RmRow>(end);
    fbb_.Required(o, RmRow::VT_ROW);
    return o;
  }
};

inline ::flatbuffers::Offset<RmRow> CreateRmRow(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<GenericId> row = 0) {
  RmRowBuilder builder_(_fbb);
  builder_.add_row(row);
  return builder_.Finish();
}

struct RmRow::Traits {
  using type = RmRow;
  static auto constexpr Create = CreateRmRow;
};

/// The RestoreRow operation restore a deleted row in the table
/// "Restore" is implemented by setting the value of the `ul_keep` system column to true.
/// This means that formerly "removed" rows are no longer treated as "removed" and will then be returned by queries.
struct RestoreRow FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef RestoreRowBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_ROW = 4
  };
  /// The value of the ul_node_id column, which uniquely identifies the row.
  const GenericId *row() const {
    return GetPointer<const GenericId *>(VT_ROW);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_ROW) &&
           verifier.VerifyTable(row()) &&
           verifier.EndTable();
  }
};

struct RestoreRowBuilder {
  typedef RestoreRow Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_row(::flatbuffers::Offset<GenericId> row) {
    fbb_.AddOffset(RestoreRow::VT_ROW, row);
  }
  explicit RestoreRowBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<RestoreRow> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<RestoreRow>(end);
    fbb_.Required(o, RestoreRow::VT_ROW);
    return o;
  }
};

inline ::flatbuffers::Offset<RestoreRow> CreateRestoreRow(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<GenericId> row = 0) {
  RestoreRowBuilder builder_(_fbb);
  builder_.add_row(row);
  return builder_.Finish();
}

struct RestoreRow::Traits {
  using type = RestoreRow;
  static auto constexpr Create = CreateRestoreRow;
};

struct OpEntry FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef OpEntryBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_OP_TYPE = 4,
    VT_OP = 6
  };
  Op op_type() const {
    return static_cast<Op>(GetField<uint8_t>(VT_OP_TYPE, 0));
  }
  const void *op() const {
    return GetPointer<const void *>(VT_OP);
  }
  template<typename T> const T *op_as() const;
  const Set *op_as_Set() const {
    return op_type() == Op::Set ? static_cast<const Set *>(op()) : nullptr;
  }
  const RmRow *op_as_RmRow() const {
    return op_type() == Op::RmRow ? static_cast<const RmRow *>(op()) : nullptr;
  }
  const RestoreRow *op_as_RestoreRow() const {
    return op_type() == Op::RestoreRow ? static_cast<const RestoreRow *>(op()) : nullptr;
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<uint8_t>(verifier, VT_OP_TYPE, 1) &&
           VerifyOffsetRequired(verifier, VT_OP) &&
           VerifyOp(verifier, op(), op_type()) &&
           verifier.EndTable();
  }
};

template<> inline const Set *OpEntry::op_as<Set>() const {
  return op_as_Set();
}

template<> inline const RmRow *OpEntry::op_as<RmRow>() const {
  return op_as_RmRow();
}

template<> inline const RestoreRow *OpEntry::op_as<RestoreRow>() const {
  return op_as_RestoreRow();
}

struct OpEntryBuilder {
  typedef OpEntry Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_op_type(Op op_type) {
    fbb_.AddElement<uint8_t>(OpEntry::VT_OP_TYPE, static_cast<uint8_t>(op_type), 0);
  }
  void add_op(::flatbuffers::Offset<void> op) {
    fbb_.AddOffset(OpEntry::VT_OP, op);
  }
  explicit OpEntryBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<OpEntry> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<OpEntry>(end);
    fbb_.Required(o, OpEntry::VT_OP);
    return o;
  }
};

inline ::flatbuffers::Offset<OpEntry> CreateOpEntry(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    Op op_type = Op::NONE,
    ::flatbuffers::Offset<void> op = 0) {
  OpEntryBuilder builder_(_fbb);
  builder_.add_op(op);
  builder_.add_op_type(op_type);
  return builder_.Finish();
}

struct OpEntry::Traits {
  using type = OpEntry;
  static auto constexpr Create = CreateOpEntry;
};

/// A DiffStream encodes a sequence of operations that should be performed on a table.
/// The operations are applied in order to the table, i.e. the ordering of the `seq` field is significant.
struct DiffStream FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef DiffStreamBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_BASE = 4,
    VT_SEQ = 6,
    VT_ATTRIBUTES = 8
  };
  /// This is the head revision of the directory object that contains the table.
  const ContentId *base() const {
    return GetPointer<const ContentId *>(VT_BASE);
  }
  const ::flatbuffers::Vector<::flatbuffers::Offset<OpEntry>> *seq() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<OpEntry>> *>(VT_SEQ);
  }
  /// We can optionally associate attributes with the diffstream.
  /// When the change history of the table is retrieved, the attributes from the diffstream
  /// will be accessible as the `attributes` field on the ChangeSet associated with this diffstream.
  const ::flatbuffers::Vector<::flatbuffers::Offset<Attr>> *attributes() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<Attr>> *>(VT_ATTRIBUTES);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_BASE) &&
           verifier.VerifyTable(base()) &&
           VerifyOffsetRequired(verifier, VT_SEQ) &&
           verifier.VerifyVector(seq()) &&
           verifier.VerifyVectorOfTables(seq()) &&
           VerifyOffset(verifier, VT_ATTRIBUTES) &&
           verifier.VerifyVector(attributes()) &&
           verifier.VerifyVectorOfTables(attributes()) &&
           verifier.EndTable();
  }
};

struct DiffStreamBuilder {
  typedef DiffStream Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_base(::flatbuffers::Offset<ContentId> base) {
    fbb_.AddOffset(DiffStream::VT_BASE, base);
  }
  void add_seq(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<OpEntry>>> seq) {
    fbb_.AddOffset(DiffStream::VT_SEQ, seq);
  }
  void add_attributes(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<Attr>>> attributes) {
    fbb_.AddOffset(DiffStream::VT_ATTRIBUTES, attributes);
  }
  explicit DiffStreamBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<DiffStream> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<DiffStream>(end);
    fbb_.Required(o, DiffStream::VT_BASE);
    fbb_.Required(o, DiffStream::VT_SEQ);
    return o;
  }
};

inline ::flatbuffers::Offset<DiffStream> CreateDiffStream(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<ContentId> base = 0,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<OpEntry>>> seq = 0,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<Attr>>> attributes = 0) {
  DiffStreamBuilder builder_(_fbb);
  builder_.add_attributes(attributes);
  builder_.add_seq(seq);
  builder_.add_base(base);
  return builder_.Finish();
}

struct DiffStream::Traits {
  using type = DiffStream;
  static auto constexpr Create = CreateDiffStream;
};

inline ::flatbuffers::Offset<DiffStream> CreateDiffStreamDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<ContentId> base = 0,
    const std::vector<::flatbuffers::Offset<OpEntry>> *seq = nullptr,
    const std::vector<::flatbuffers::Offset<Attr>> *attributes = nullptr) {
  auto seq__ = seq ? _fbb.CreateVector<::flatbuffers::Offset<OpEntry>>(*seq) : 0;
  auto attributes__ = attributes ? _fbb.CreateVector<::flatbuffers::Offset<Attr>>(*attributes) : 0;
  return CreateDiffStream(
      _fbb,
      base,
      seq__,
      attributes__);
}

/// Body parameter for POST datacatalog/table/<objectId>
struct NewTable FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef NewTableBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_NAME = 4,
    VT_PARENT = 6,
    VT_TARGET = 8
  };
  const ::flatbuffers::String *name() const {
    return GetPointer<const ::flatbuffers::String *>(VT_NAME);
  }
  const ObjectId *parent() const {
    return GetPointer<const ObjectId *>(VT_PARENT);
  }
  /// If specified, creates a new table using this as the object ID.
  const ObjectId *target() const {
    return GetPointer<const ObjectId *>(VT_TARGET);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_NAME) &&
           verifier.VerifyString(name()) &&
           VerifyOffset(verifier, VT_PARENT) &&
           verifier.VerifyTable(parent()) &&
           VerifyOffset(verifier, VT_TARGET) &&
           verifier.VerifyTable(target()) &&
           verifier.EndTable();
  }
};

struct NewTableBuilder {
  typedef NewTable Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_name(::flatbuffers::Offset<::flatbuffers::String> name) {
    fbb_.AddOffset(NewTable::VT_NAME, name);
  }
  void add_parent(::flatbuffers::Offset<ObjectId> parent) {
    fbb_.AddOffset(NewTable::VT_PARENT, parent);
  }
  void add_target(::flatbuffers::Offset<ObjectId> target) {
    fbb_.AddOffset(NewTable::VT_TARGET, target);
  }
  explicit NewTableBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<NewTable> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<NewTable>(end);
    fbb_.Required(o, NewTable::VT_NAME);
    return o;
  }
};

inline ::flatbuffers::Offset<NewTable> CreateNewTable(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<::flatbuffers::String> name = 0,
    ::flatbuffers::Offset<ObjectId> parent = 0,
    ::flatbuffers::Offset<ObjectId> target = 0) {
  NewTableBuilder builder_(_fbb);
  builder_.add_target(target);
  builder_.add_parent(parent);
  builder_.add_name(name);
  return builder_.Finish();
}

struct NewTable::Traits {
  using type = NewTable;
  static auto constexpr Create = CreateNewTable;
};

inline ::flatbuffers::Offset<NewTable> CreateNewTableDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    const char *name = nullptr,
    ::flatbuffers::Offset<ObjectId> parent = 0,
    ::flatbuffers::Offset<ObjectId> target = 0) {
  auto name__ = name ? _fbb.CreateString(name) : 0;
  return CreateNewTable(
      _fbb,
      name__,
      parent,
      target);
}

struct Modify FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef ModifyBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_COL = 4,
    VT_VALUE = 6,
    VT_PREVIOUS = 8,
    VT_ROW = 10
  };
  const ::flatbuffers::String *col() const {
    return GetPointer<const ::flatbuffers::String *>(VT_COL);
  }
  const ValueInstance *value() const {
    return GetPointer<const ValueInstance *>(VT_VALUE);
  }
  const ValueInstance *previous() const {
    return GetPointer<const ValueInstance *>(VT_PREVIOUS);
  }
  const GenericId *row() const {
    return GetPointer<const GenericId *>(VT_ROW);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_COL) &&
           verifier.VerifyString(col()) &&
           VerifyOffsetRequired(verifier, VT_VALUE) &&
           verifier.VerifyTable(value()) &&
           VerifyOffset(verifier, VT_PREVIOUS) &&
           verifier.VerifyTable(previous()) &&
           VerifyOffsetRequired(verifier, VT_ROW) &&
           verifier.VerifyTable(row()) &&
           verifier.EndTable();
  }
};

struct ModifyBuilder {
  typedef Modify Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_col(::flatbuffers::Offset<::flatbuffers::String> col) {
    fbb_.AddOffset(Modify::VT_COL, col);
  }
  void add_value(::flatbuffers::Offset<ValueInstance> value) {
    fbb_.AddOffset(Modify::VT_VALUE, value);
  }
  void add_previous(::flatbuffers::Offset<ValueInstance> previous) {
    fbb_.AddOffset(Modify::VT_PREVIOUS, previous);
  }
  void add_row(::flatbuffers::Offset<GenericId> row) {
    fbb_.AddOffset(Modify::VT_ROW, row);
  }
  explicit ModifyBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<Modify> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<Modify>(end);
    fbb_.Required(o, Modify::VT_COL);
    fbb_.Required(o, Modify::VT_VALUE);
    fbb_.Required(o, Modify::VT_ROW);
    return o;
  }
};

inline ::flatbuffers::Offset<Modify> CreateModify(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<::flatbuffers::String> col = 0,
    ::flatbuffers::Offset<ValueInstance> value = 0,
    ::flatbuffers::Offset<ValueInstance> previous = 0,
    ::flatbuffers::Offset<GenericId> row = 0) {
  ModifyBuilder builder_(_fbb);
  builder_.add_row(row);
  builder_.add_previous(previous);
  builder_.add_value(value);
  builder_.add_col(col);
  return builder_.Finish();
}

struct Modify::Traits {
  using type = Modify;
  static auto constexpr Create = CreateModify;
};

inline ::flatbuffers::Offset<Modify> CreateModifyDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    const char *col = nullptr,
    ::flatbuffers::Offset<ValueInstance> value = 0,
    ::flatbuffers::Offset<ValueInstance> previous = 0,
    ::flatbuffers::Offset<GenericId> row = 0) {
  auto col__ = col ? _fbb.CreateString(col) : 0;
  return CreateModify(
      _fbb,
      col__,
      value,
      previous,
      row);
}

struct Delete FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef DeleteBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_ROW = 4
  };
  const GenericId *row() const {
    return GetPointer<const GenericId *>(VT_ROW);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_ROW) &&
           verifier.VerifyTable(row()) &&
           verifier.EndTable();
  }
};

struct DeleteBuilder {
  typedef Delete Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_row(::flatbuffers::Offset<GenericId> row) {
    fbb_.AddOffset(Delete::VT_ROW, row);
  }
  explicit DeleteBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<Delete> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<Delete>(end);
    fbb_.Required(o, Delete::VT_ROW);
    return o;
  }
};

inline ::flatbuffers::Offset<Delete> CreateDelete(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<GenericId> row = 0) {
  DeleteBuilder builder_(_fbb);
  builder_.add_row(row);
  return builder_.Finish();
}

struct Delete::Traits {
  using type = Delete;
  static auto constexpr Create = CreateDelete;
};

struct Restore FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef RestoreBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_ROW = 4
  };
  const GenericId *row() const {
    return GetPointer<const GenericId *>(VT_ROW);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_ROW) &&
           verifier.VerifyTable(row()) &&
           verifier.EndTable();
  }
};

struct RestoreBuilder {
  typedef Restore Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_row(::flatbuffers::Offset<GenericId> row) {
    fbb_.AddOffset(Restore::VT_ROW, row);
  }
  explicit RestoreBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<Restore> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<Restore>(end);
    fbb_.Required(o, Restore::VT_ROW);
    return o;
  }
};

inline ::flatbuffers::Offset<Restore> CreateRestore(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<GenericId> row = 0) {
  RestoreBuilder builder_(_fbb);
  builder_.add_row(row);
  return builder_.Finish();
}

struct Restore::Traits {
  using type = Restore;
  static auto constexpr Create = CreateRestore;
};

struct ChangeOpEntry FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef ChangeOpEntryBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_OP_TYPE = 4,
    VT_OP = 6
  };
  ChangeOp op_type() const {
    return static_cast<ChangeOp>(GetField<uint8_t>(VT_OP_TYPE, 0));
  }
  const void *op() const {
    return GetPointer<const void *>(VT_OP);
  }
  template<typename T> const T *op_as() const;
  const Modify *op_as_Modify() const {
    return op_type() == ChangeOp::Modify ? static_cast<const Modify *>(op()) : nullptr;
  }
  const Delete *op_as_Delete() const {
    return op_type() == ChangeOp::Delete ? static_cast<const Delete *>(op()) : nullptr;
  }
  const Restore *op_as_Restore() const {
    return op_type() == ChangeOp::Restore ? static_cast<const Restore *>(op()) : nullptr;
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<uint8_t>(verifier, VT_OP_TYPE, 1) &&
           VerifyOffsetRequired(verifier, VT_OP) &&
           VerifyChangeOp(verifier, op(), op_type()) &&
           verifier.EndTable();
  }
};

template<> inline const Modify *ChangeOpEntry::op_as<Modify>() const {
  return op_as_Modify();
}

template<> inline const Delete *ChangeOpEntry::op_as<Delete>() const {
  return op_as_Delete();
}

template<> inline const Restore *ChangeOpEntry::op_as<Restore>() const {
  return op_as_Restore();
}

struct ChangeOpEntryBuilder {
  typedef ChangeOpEntry Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_op_type(ChangeOp op_type) {
    fbb_.AddElement<uint8_t>(ChangeOpEntry::VT_OP_TYPE, static_cast<uint8_t>(op_type), 0);
  }
  void add_op(::flatbuffers::Offset<void> op) {
    fbb_.AddOffset(ChangeOpEntry::VT_OP, op);
  }
  explicit ChangeOpEntryBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<ChangeOpEntry> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<ChangeOpEntry>(end);
    fbb_.Required(o, ChangeOpEntry::VT_OP);
    return o;
  }
};

inline ::flatbuffers::Offset<ChangeOpEntry> CreateChangeOpEntry(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ChangeOp op_type = ChangeOp::NONE,
    ::flatbuffers::Offset<void> op = 0) {
  ChangeOpEntryBuilder builder_(_fbb);
  builder_.add_op(op);
  builder_.add_op_type(op_type);
  return builder_.Finish();
}

struct ChangeOpEntry::Traits {
  using type = ChangeOpEntry;
  static auto constexpr Create = CreateChangeOpEntry;
};

struct ChangeSet FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef ChangeSetBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_REVISION = 4,
    VT_WHO = 6,
    VT_WHEN = 8,
    VT_OPS = 10,
    VT_ATTRIBUTES = 12
  };
  const ContentId *revision() const {
    return GetPointer<const ContentId *>(VT_REVISION);
  }
  const B2cId *who() const {
    return GetPointer<const B2cId *>(VT_WHO);
  }
  uint64_t when() const {
    return GetField<uint64_t>(VT_WHEN, 0);
  }
  const ::flatbuffers::Vector<::flatbuffers::Offset<ChangeOpEntry>> *ops() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<ChangeOpEntry>> *>(VT_OPS);
  }
  const ::flatbuffers::Vector<::flatbuffers::Offset<Attr>> *attributes() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<Attr>> *>(VT_ATTRIBUTES);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_REVISION) &&
           verifier.VerifyTable(revision()) &&
           VerifyOffsetRequired(verifier, VT_WHO) &&
           verifier.VerifyTable(who()) &&
           VerifyField<uint64_t>(verifier, VT_WHEN, 8) &&
           VerifyOffsetRequired(verifier, VT_OPS) &&
           verifier.VerifyVector(ops()) &&
           verifier.VerifyVectorOfTables(ops()) &&
           VerifyOffset(verifier, VT_ATTRIBUTES) &&
           verifier.VerifyVector(attributes()) &&
           verifier.VerifyVectorOfTables(attributes()) &&
           verifier.EndTable();
  }
};

struct ChangeSetBuilder {
  typedef ChangeSet Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_revision(::flatbuffers::Offset<ContentId> revision) {
    fbb_.AddOffset(ChangeSet::VT_REVISION, revision);
  }
  void add_who(::flatbuffers::Offset<B2cId> who) {
    fbb_.AddOffset(ChangeSet::VT_WHO, who);
  }
  void add_when(uint64_t when) {
    fbb_.AddElement<uint64_t>(ChangeSet::VT_WHEN, when, 0);
  }
  void add_ops(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<ChangeOpEntry>>> ops) {
    fbb_.AddOffset(ChangeSet::VT_OPS, ops);
  }
  void add_attributes(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<Attr>>> attributes) {
    fbb_.AddOffset(ChangeSet::VT_ATTRIBUTES, attributes);
  }
  explicit ChangeSetBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<ChangeSet> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<ChangeSet>(end);
    fbb_.Required(o, ChangeSet::VT_REVISION);
    fbb_.Required(o, ChangeSet::VT_WHO);
    fbb_.Required(o, ChangeSet::VT_OPS);
    return o;
  }
};

inline ::flatbuffers::Offset<ChangeSet> CreateChangeSet(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<ContentId> revision = 0,
    ::flatbuffers::Offset<B2cId> who = 0,
    uint64_t when = 0,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<ChangeOpEntry>>> ops = 0,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<Attr>>> attributes = 0) {
  ChangeSetBuilder builder_(_fbb);
  builder_.add_when(when);
  builder_.add_attributes(attributes);
  builder_.add_ops(ops);
  builder_.add_who(who);
  builder_.add_revision(revision);
  return builder_.Finish();
}

struct ChangeSet::Traits {
  using type = ChangeSet;
  static auto constexpr Create = CreateChangeSet;
};

inline ::flatbuffers::Offset<ChangeSet> CreateChangeSetDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<ContentId> revision = 0,
    ::flatbuffers::Offset<B2cId> who = 0,
    uint64_t when = 0,
    const std::vector<::flatbuffers::Offset<ChangeOpEntry>> *ops = nullptr,
    const std::vector<::flatbuffers::Offset<Attr>> *attributes = nullptr) {
  auto ops__ = ops ? _fbb.CreateVector<::flatbuffers::Offset<ChangeOpEntry>>(*ops) : 0;
  auto attributes__ = attributes ? _fbb.CreateVector<::flatbuffers::Offset<Attr>>(*attributes) : 0;
  return CreateChangeSet(
      _fbb,
      revision,
      who,
      when,
      ops__,
      attributes__);
}

struct History FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef HistoryBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_CHANGES = 4,
    VT_CONTINUATION_ID = 6
  };
  const ::flatbuffers::Vector<::flatbuffers::Offset<ChangeSet>> *changes() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<ChangeSet>> *>(VT_CHANGES);
  }
  const ContentId *continuation_id() const {
    return GetPointer<const ContentId *>(VT_CONTINUATION_ID);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_CHANGES) &&
           verifier.VerifyVector(changes()) &&
           verifier.VerifyVectorOfTables(changes()) &&
           VerifyOffset(verifier, VT_CONTINUATION_ID) &&
           verifier.VerifyTable(continuation_id()) &&
           verifier.EndTable();
  }
};

struct HistoryBuilder {
  typedef History Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_changes(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<ChangeSet>>> changes) {
    fbb_.AddOffset(History::VT_CHANGES, changes);
  }
  void add_continuation_id(::flatbuffers::Offset<ContentId> continuation_id) {
    fbb_.AddOffset(History::VT_CONTINUATION_ID, continuation_id);
  }
  explicit HistoryBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<History> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<History>(end);
    fbb_.Required(o, History::VT_CHANGES);
    return o;
  }
};

inline ::flatbuffers::Offset<History> CreateHistory(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<ChangeSet>>> changes = 0,
    ::flatbuffers::Offset<ContentId> continuation_id = 0) {
  HistoryBuilder builder_(_fbb);
  builder_.add_continuation_id(continuation_id);
  builder_.add_changes(changes);
  return builder_.Finish();
}

struct History::Traits {
  using type = History;
  static auto constexpr Create = CreateHistory;
};

inline ::flatbuffers::Offset<History> CreateHistoryDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<::flatbuffers::Offset<ChangeSet>> *changes = nullptr,
    ::flatbuffers::Offset<ContentId> continuation_id = 0) {
  auto changes__ = changes ? _fbb.CreateVector<::flatbuffers::Offset<ChangeSet>>(*changes) : 0;
  return CreateHistory(
      _fbb,
      changes__,
      continuation_id);
}

inline bool VerifyOp(::flatbuffers::Verifier &verifier, const void *obj, Op type) {
  switch (type) {
    case Op::NONE: {
      return true;
    }
    case Op::Set: {
      auto ptr = reinterpret_cast<const Set *>(obj);
      return verifier.VerifyTable(ptr);
    }
    case Op::RmRow: {
      auto ptr = reinterpret_cast<const RmRow *>(obj);
      return verifier.VerifyTable(ptr);
    }
    case Op::RestoreRow: {
      auto ptr = reinterpret_cast<const RestoreRow *>(obj);
      return verifier.VerifyTable(ptr);
    }
    default: return true;
  }
}

inline bool VerifyOpVector(::flatbuffers::Verifier &verifier, const ::flatbuffers::Vector<::flatbuffers::Offset<void>> *values, const ::flatbuffers::Vector<Op> *types) {
  if (!values || !types) return !values && !types;
  if (values->size() != types->size()) return false;
  for (::flatbuffers::uoffset_t i = 0; i < values->size(); ++i) {
    if (!VerifyOp(
        verifier,  values->Get(i), types->GetEnum<Op>(i))) {
      return false;
    }
  }
  return true;
}

inline bool VerifyChangeOp(::flatbuffers::Verifier &verifier, const void *obj, ChangeOp type) {
  switch (type) {
    case ChangeOp::NONE: {
      return true;
    }
    case ChangeOp::Modify: {
      auto ptr = reinterpret_cast<const Modify *>(obj);
      return verifier.VerifyTable(ptr);
    }
    case ChangeOp::Delete: {
      auto ptr = reinterpret_cast<const Delete *>(obj);
      return verifier.VerifyTable(ptr);
    }
    case ChangeOp::Restore: {
      auto ptr = reinterpret_cast<const Restore *>(obj);
      return verifier.VerifyTable(ptr);
    }
    default: return true;
  }
}

inline bool VerifyChangeOpVector(::flatbuffers::Verifier &verifier, const ::flatbuffers::Vector<::flatbuffers::Offset<void>> *values, const ::flatbuffers::Vector<ChangeOp> *types) {
  if (!values || !types) return !values && !types;
  if (values->size() != types->size()) return false;
  for (::flatbuffers::uoffset_t i = 0; i < values->size(); ++i) {
    if (!VerifyChangeOp(
        verifier,  values->Get(i), types->GetEnum<ChangeOp>(i))) {
      return false;
    }
  }
  return true;
}

#endif  // FLATBUFFERS_GENERATED_TABLE_H_
