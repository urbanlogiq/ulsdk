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
#include "ulsdk/types/generated/reflection_generated.h"

namespace ul {
namespace types {

namespace reflection {
struct Enum;
} // namespace reflection
namespace reflection {
struct EnumVal;
} // namespace reflection
namespace reflection {
struct Field;
} // namespace reflection
namespace reflection {
struct KeyValue;
} // namespace reflection
namespace reflection {
struct Object;
} // namespace reflection
namespace reflection {
struct RPCCall;
} // namespace reflection
namespace reflection {
struct Schema;
} // namespace reflection
namespace reflection {
struct SchemaFile;
} // namespace reflection
namespace reflection {
struct Service;
} // namespace reflection
namespace reflection {
struct Type;
} // namespace reflection

using ::reflection::AdvancedFeatures;
using ::reflection::BaseType;
struct reflection::Type {
    uint32_t base_size_;
    BaseType base_type_;
    BaseType element_;
    uint32_t element_size_;
    uint16_t fixed_length_;
    int32_t index_;

    Type();
    Type(const ::reflection::Type *root);
    Type(const std::vector<uint8_t> &bytes);
};

struct reflection::Enum {
    std::optional<std::vector<reflection::KeyValue>> attributes_;
    std::optional<std::string> declaration_file_;
    std::optional<std::vector<std::string>> documentation_;
    bool is_union_;
    std::string name_;
    Type underlying_type_;
    std::vector<reflection::EnumVal> values_;

    Enum();
    Enum(const ::reflection::Enum *root);
    Enum(const std::vector<uint8_t> &bytes);
};

struct reflection::Object {
    std::optional<std::vector<reflection::KeyValue>> attributes_;
    int32_t bytesize_;
    std::optional<std::string> declaration_file_;
    std::optional<std::vector<std::string>> documentation_;
    std::vector<reflection::Field> fields_;
    bool is_struct_;
    int32_t minalign_;
    std::string name_;

    Object();
    Object(const ::reflection::Object *root);
    Object(const std::vector<uint8_t> &bytes);
};

struct reflection::EnumVal {
    std::optional<std::vector<reflection::KeyValue>> attributes_;
    std::optional<std::vector<std::string>> documentation_;
    std::string name_;
    std::optional<Type> union_type_;
    int64_t value_;

    EnumVal();
    EnumVal(const ::reflection::EnumVal *root);
    EnumVal(const std::vector<uint8_t> &bytes);
};

struct reflection::Field {
    std::optional<std::vector<reflection::KeyValue>> attributes_;
    int64_t default_integer_;
    double default_real_;
    bool deprecated_;
    std::optional<std::vector<std::string>> documentation_;
    uint16_t id_;
    bool key_;
    std::string name_;
    uint16_t offset_;
    bool offset64_;
    bool optional_;
    uint16_t padding_;
    bool required_;
    Type type_;

    Field();
    Field(const ::reflection::Field *root);
    Field(const std::vector<uint8_t> &bytes);
};

struct reflection::KeyValue {
    std::string key_;
    std::optional<std::string> value_;

    KeyValue();
    KeyValue(const ::reflection::KeyValue *root);
    KeyValue(const std::vector<uint8_t> &bytes);
};

struct reflection::RPCCall {
    std::optional<std::vector<reflection::KeyValue>> attributes_;
    std::optional<std::vector<std::string>> documentation_;
    std::string name_;
    Object request_;
    Object response_;

    RPCCall();
    RPCCall(const ::reflection::RPCCall *root);
    RPCCall(const std::vector<uint8_t> &bytes);
};

struct reflection::Schema {
    AdvancedFeatures advanced_features_;
    std::vector<reflection::Enum> enums_;
    std::optional<std::vector<reflection::SchemaFile>> fbs_files_;
    std::optional<std::string> file_ext_;
    std::optional<std::string> file_ident_;
    std::vector<reflection::Object> objects_;
    std::optional<Object> root_table_;
    std::optional<std::vector<reflection::Service>> services_;

    Schema();
    Schema(const ::reflection::Schema *root);
    Schema(const std::vector<uint8_t> &bytes);
};

///
/// File specific information.
/// Symbols declared within a file may be recovered by iterating over all
/// symbols and examining the `declaration_file` field.
///
struct reflection::SchemaFile {
    std::string filename_;
    std::optional<std::vector<std::string>> included_filenames_;

    SchemaFile();
    SchemaFile(const ::reflection::SchemaFile *root);
    SchemaFile(const std::vector<uint8_t> &bytes);
};

struct reflection::Service {
    std::optional<std::vector<reflection::KeyValue>> attributes_;
    std::optional<std::vector<reflection::RPCCall>> calls_;
    std::optional<std::string> declaration_file_;
    std::optional<std::vector<std::string>> documentation_;
    std::string name_;

    Service();
    Service(const ::reflection::Service *root);
    Service(const std::vector<uint8_t> &bytes);
};

::flatbuffers::Offset<::reflection::Type>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const reflection::Type &);

::flatbuffers::Offset<::reflection::Enum>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const reflection::Enum &);

::flatbuffers::Offset<::reflection::Object>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const reflection::Object &);

::flatbuffers::Offset<::reflection::EnumVal>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const reflection::EnumVal &);

::flatbuffers::Offset<::reflection::Field>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const reflection::Field &);

::flatbuffers::Offset<::reflection::KeyValue>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const reflection::KeyValue &);

::flatbuffers::Offset<::reflection::RPCCall>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const reflection::RPCCall &);

::flatbuffers::Offset<::reflection::Schema>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const reflection::Schema &);

::flatbuffers::Offset<::reflection::SchemaFile>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const reflection::SchemaFile &);

::flatbuffers::Offset<::reflection::Service>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const reflection::Service &);


std::vector<uint8_t>
to_bytes(const reflection::Type &o);

std::vector<uint8_t>
to_bytes(const reflection::Enum &o);

std::vector<uint8_t>
to_bytes(const reflection::Object &o);

std::vector<uint8_t>
to_bytes(const reflection::EnumVal &o);

std::vector<uint8_t>
to_bytes(const reflection::Field &o);

std::vector<uint8_t>
to_bytes(const reflection::KeyValue &o);

std::vector<uint8_t>
to_bytes(const reflection::RPCCall &o);

std::vector<uint8_t>
to_bytes(const reflection::Schema &o);

std::vector<uint8_t>
to_bytes(const reflection::SchemaFile &o);

std::vector<uint8_t>
to_bytes(const reflection::Service &o);


} // namespace types
} // namespace ul
