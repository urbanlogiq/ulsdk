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
#include "ulsdk/types/Schema.h"
#include "ulsdk/types/api.h"
#include "ulsdk/types/crypto.h"
#include "ulsdk/types/data.h"
#include "ulsdk/types/entity.h"
#include "ulsdk/types/fs.h"
#include "ulsdk/types/fun.h"
#include "ulsdk/types/graph.h"
#include "ulsdk/types/id.h"
#include "ulsdk/types/job.h"
#include "ulsdk/types/object.h"
#include "ulsdk/types/query.h"
#include "ulsdk/types/reflection.h"
#include "ulsdk/types/stream.h"
#include "ulsdk/types/value.h"
#include "ulsdk/types/worklog.h"
#include "ulsdk/types/generated/table_generated.h"

namespace ul {
namespace types {

struct ChangeOpEntry;
struct ChangeSet;
struct Delete;
struct DiffStream;
struct History;
struct Modify;
struct NewTable;
struct OpEntry;
struct Restore;
struct RestoreRow;
struct RmRow;
struct Set;

typedef std::variant<
    std::shared_ptr<Modify>,
    std::shared_ptr<Delete>,
    std::shared_ptr<Restore>
> ChangeOp;

typedef std::variant<
    std::shared_ptr<Set>,
    std::shared_ptr<RmRow>,
    std::shared_ptr<RestoreRow>
> Op;

struct Modify {
    std::string col_;
    std::optional<ValueInstance> previous_;
    GenericId row_;
    ValueInstance value_;

    Modify();
    Modify(const ::Modify *root);
    Modify(const std::vector<uint8_t> &bytes);
};

struct Delete {
    GenericId row_;

    Delete();
    Delete(const ::Delete *root);
    Delete(const std::vector<uint8_t> &bytes);
};

struct Restore {
    GenericId row_;

    Restore();
    Restore(const ::Restore *root);
    Restore(const std::vector<uint8_t> &bytes);
};

struct Set {
    std::string col_;
    GenericId row_;
    ValueInstance value_;

    Set();
    Set(const ::Set *root);
    Set(const std::vector<uint8_t> &bytes);
};

struct RmRow {
    GenericId row_;

    RmRow();
    RmRow(const ::RmRow *root);
    RmRow(const std::vector<uint8_t> &bytes);
};

struct RestoreRow {
    GenericId row_;

    RestoreRow();
    RestoreRow(const ::RestoreRow *root);
    RestoreRow(const std::vector<uint8_t> &bytes);
};

struct ChangeOpEntry {
    ChangeOp op_;

    ChangeOpEntry();
    ChangeOpEntry(const ::ChangeOpEntry *root);
    ChangeOpEntry(const std::vector<uint8_t> &bytes);
};

struct ChangeSet {
    std::optional<std::vector<Attr>> attributes_;
    std::vector<ChangeOpEntry> ops_;
    ContentId revision_;
    uint64_t when_;
    B2cId who_;

    ChangeSet();
    ChangeSet(const ::ChangeSet *root);
    ChangeSet(const std::vector<uint8_t> &bytes);
};

struct DiffStream {
    std::optional<std::vector<Attr>> attributes_;
    ContentId base_;
    std::vector<OpEntry> seq_;

    DiffStream();
    DiffStream(const ::DiffStream *root);
    DiffStream(const std::vector<uint8_t> &bytes);
};

struct History {
    std::vector<ChangeSet> changes_;
    std::optional<ContentId> continuation_id_;

    History();
    History(const ::History *root);
    History(const std::vector<uint8_t> &bytes);
};

struct NewTable {
    std::string name_;
    std::optional<ObjectId> parent_;
    std::optional<ObjectId> target_;

    NewTable();
    NewTable(const ::NewTable *root);
    NewTable(const std::vector<uint8_t> &bytes);
};

struct OpEntry {
    Op op_;

    OpEntry();
    OpEntry(const ::OpEntry *root);
    OpEntry(const std::vector<uint8_t> &bytes);
};

std::pair<::flatbuffers::Offset<void>, ::ChangeOp>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const ChangeOp &o);
std::pair<::flatbuffers::Offset<void>, ::Op>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Op &o);
::flatbuffers::Offset<::Modify>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Modify &);

::flatbuffers::Offset<::Delete>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Delete &);

::flatbuffers::Offset<::Restore>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Restore &);

::flatbuffers::Offset<::Set>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Set &);

::flatbuffers::Offset<::RmRow>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const RmRow &);

::flatbuffers::Offset<::RestoreRow>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const RestoreRow &);

::flatbuffers::Offset<::ChangeOpEntry>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const ChangeOpEntry &);

::flatbuffers::Offset<::ChangeSet>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const ChangeSet &);

::flatbuffers::Offset<::DiffStream>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const DiffStream &);

::flatbuffers::Offset<::History>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const History &);

::flatbuffers::Offset<::NewTable>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const NewTable &);

::flatbuffers::Offset<::OpEntry>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const OpEntry &);


std::vector<uint8_t>
to_bytes(const Modify &o);

std::vector<uint8_t>
to_bytes(const Delete &o);

std::vector<uint8_t>
to_bytes(const Restore &o);

std::vector<uint8_t>
to_bytes(const Set &o);

std::vector<uint8_t>
to_bytes(const RmRow &o);

std::vector<uint8_t>
to_bytes(const RestoreRow &o);

std::vector<uint8_t>
to_bytes(const ChangeOpEntry &o);

std::vector<uint8_t>
to_bytes(const ChangeSet &o);

std::vector<uint8_t>
to_bytes(const DiffStream &o);

std::vector<uint8_t>
to_bytes(const History &o);

std::vector<uint8_t>
to_bytes(const NewTable &o);

std::vector<uint8_t>
to_bytes(const OpEntry &o);


} // namespace types
} // namespace ul