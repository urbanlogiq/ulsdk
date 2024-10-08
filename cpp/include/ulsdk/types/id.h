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
#include "ulsdk/types/generated/id_generated.h"

namespace ul {
namespace types {

struct B2cId;
struct ColumnGroupId;
struct ContentId;
struct DataStateId;
struct GenericId;
struct GraphNodeId;
struct ObjectId;
struct StreamId;

using ::ObjectNamespace;
struct B2cId {
    std::vector<uint8_t> b_;

    B2cId();
    B2cId(const ::B2cId *root);
    B2cId(const std::vector<uint8_t> &bytes);
};

struct ColumnGroupId {
    std::vector<uint8_t> b_;

    ColumnGroupId();
    ColumnGroupId(const ::ColumnGroupId *root);
    ColumnGroupId(const std::vector<uint8_t> &bytes);
};

struct ContentId {
    std::vector<uint8_t> b_;

    ContentId();
    ContentId(const ::ContentId *root);
    ContentId(const std::vector<uint8_t> &bytes);
};

struct DataStateId {
    std::vector<uint8_t> b_;

    DataStateId();
    DataStateId(const ::DataStateId *root);
    DataStateId(const std::vector<uint8_t> &bytes);
};

struct GenericId {
    std::vector<uint8_t> b_;

    GenericId();
    GenericId(const ::GenericId *root);
    GenericId(const std::vector<uint8_t> &bytes);
};

struct GraphNodeId {
    std::vector<uint8_t> b_;

    GraphNodeId();
    GraphNodeId(const ::GraphNodeId *root);
    GraphNodeId(const std::vector<uint8_t> &bytes);
};

struct ObjectId {
    std::vector<uint8_t> b_;

    ObjectId();
    ObjectId(const ::ObjectId *root);
    ObjectId(const std::vector<uint8_t> &bytes);
};

struct StreamId {
    std::vector<uint8_t> b_;

    StreamId();
    StreamId(const ::StreamId *root);
    StreamId(const std::vector<uint8_t> &bytes);
};

::flatbuffers::Offset<::B2cId>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const B2cId &);

::flatbuffers::Offset<::ColumnGroupId>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const ColumnGroupId &);

::flatbuffers::Offset<::ContentId>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const ContentId &);

::flatbuffers::Offset<::DataStateId>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const DataStateId &);

::flatbuffers::Offset<::GenericId>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const GenericId &);

::flatbuffers::Offset<::GraphNodeId>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const GraphNodeId &);

::flatbuffers::Offset<::ObjectId>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const ObjectId &);

::flatbuffers::Offset<::StreamId>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const StreamId &);


std::vector<uint8_t>
to_bytes(const B2cId &o);

std::vector<uint8_t>
to_bytes(const ColumnGroupId &o);

std::vector<uint8_t>
to_bytes(const ContentId &o);

std::vector<uint8_t>
to_bytes(const DataStateId &o);

std::vector<uint8_t>
to_bytes(const GenericId &o);

std::vector<uint8_t>
to_bytes(const GraphNodeId &o);

std::vector<uint8_t>
to_bytes(const ObjectId &o);

std::vector<uint8_t>
to_bytes(const StreamId &o);


} // namespace types
} // namespace ul
