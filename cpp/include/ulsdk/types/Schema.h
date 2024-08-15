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
#include "ulsdk/types/generated/Schema_generated.h"

namespace ul {
namespace types {

struct Binary;
struct Bool;
struct Buffer;
struct Date;
struct Decimal;
struct DictionaryEncoding;
struct Duration;
struct Field;
struct FixedSizeBinary;
struct FixedSizeList;
struct FloatingPoint;
struct Int;
struct Interval;
struct KeyValue;
struct LargeBinary;
struct LargeList;
struct LargeUtf8;
struct List;
struct Map;
struct Null;
struct Schema;
struct Struct_;
struct Time;
struct Timestamp;
struct Union;
struct Utf8;

using ::DateUnit;
using ::DictionaryKind;
using ::Endianness;
using ::Feature;
using ::IntervalUnit;
using ::MetadataVersion;
using ::Precision;
using ::TimeUnit;
typedef std::variant<
    std::shared_ptr<Null>,
    std::shared_ptr<Int>,
    std::shared_ptr<FloatingPoint>,
    std::shared_ptr<Binary>,
    std::shared_ptr<Utf8>,
    std::shared_ptr<Bool>,
    std::shared_ptr<Decimal>,
    std::shared_ptr<Date>,
    std::shared_ptr<Time>,
    std::shared_ptr<Timestamp>,
    std::shared_ptr<Interval>,
    std::shared_ptr<List>,
    std::shared_ptr<Struct_>,
    std::shared_ptr<Union>,
    std::shared_ptr<FixedSizeBinary>,
    std::shared_ptr<FixedSizeList>,
    std::shared_ptr<Map>,
    std::shared_ptr<Duration>,
    std::shared_ptr<LargeBinary>,
    std::shared_ptr<LargeUtf8>,
    std::shared_ptr<LargeList>
> Type;

using ::UnionMode;
struct Null {

    Null();
    Null(const ::Null *root);
    Null(const std::vector<uint8_t> &bytes);
};

struct Int {
    int32_t bitWidth_;
    bool is_signed_;

    Int();
    Int(const ::Int *root);
    Int(const std::vector<uint8_t> &bytes);
};

struct FloatingPoint {
    Precision precision_;

    FloatingPoint();
    FloatingPoint(const ::FloatingPoint *root);
    FloatingPoint(const std::vector<uint8_t> &bytes);
};

struct Binary {

    Binary();
    Binary(const ::Binary *root);
    Binary(const std::vector<uint8_t> &bytes);
};

struct Utf8 {

    Utf8();
    Utf8(const ::Utf8 *root);
    Utf8(const std::vector<uint8_t> &bytes);
};

struct Bool {

    Bool();
    Bool(const ::Bool *root);
    Bool(const std::vector<uint8_t> &bytes);
};

struct Decimal {
    int32_t bitWidth_;
    int32_t precision_;
    int32_t scale_;

    Decimal();
    Decimal(const ::Decimal *root);
    Decimal(const std::vector<uint8_t> &bytes);
};

struct Date {
    DateUnit unit_;

    Date();
    Date(const ::Date *root);
    Date(const std::vector<uint8_t> &bytes);
};

struct Time {
    int32_t bitWidth_;
    TimeUnit unit_;

    Time();
    Time(const ::Time *root);
    Time(const std::vector<uint8_t> &bytes);
};

struct Timestamp {
    std::optional<std::string> timezone_;
    TimeUnit unit_;

    Timestamp();
    Timestamp(const ::Timestamp *root);
    Timestamp(const std::vector<uint8_t> &bytes);
};

struct Interval {
    IntervalUnit unit_;

    Interval();
    Interval(const ::Interval *root);
    Interval(const std::vector<uint8_t> &bytes);
};

struct List {

    List();
    List(const ::List *root);
    List(const std::vector<uint8_t> &bytes);
};

struct Struct_ {

    Struct_();
    Struct_(const ::Struct_ *root);
    Struct_(const std::vector<uint8_t> &bytes);
};

struct Union {
    UnionMode mode_;
    std::optional<std::vector<int32_t>> typeIds_;

    Union();
    Union(const ::Union *root);
    Union(const std::vector<uint8_t> &bytes);
};

struct FixedSizeBinary {
    int32_t byteWidth_;

    FixedSizeBinary();
    FixedSizeBinary(const ::FixedSizeBinary *root);
    FixedSizeBinary(const std::vector<uint8_t> &bytes);
};

struct FixedSizeList {
    int32_t listSize_;

    FixedSizeList();
    FixedSizeList(const ::FixedSizeList *root);
    FixedSizeList(const std::vector<uint8_t> &bytes);
};

struct Map {
    bool keysSorted_;

    Map();
    Map(const ::Map *root);
    Map(const std::vector<uint8_t> &bytes);
};

struct Duration {
    TimeUnit unit_;

    Duration();
    Duration(const ::Duration *root);
    Duration(const std::vector<uint8_t> &bytes);
};

struct LargeBinary {

    LargeBinary();
    LargeBinary(const ::LargeBinary *root);
    LargeBinary(const std::vector<uint8_t> &bytes);
};

struct LargeUtf8 {

    LargeUtf8();
    LargeUtf8(const ::LargeUtf8 *root);
    LargeUtf8(const std::vector<uint8_t> &bytes);
};

struct LargeList {

    LargeList();
    LargeList(const ::LargeList *root);
    LargeList(const std::vector<uint8_t> &bytes);
};

struct Buffer {
    int64_t length_;
    int64_t offset_;

    Buffer();
    Buffer(const ::Buffer *root);
};

struct DictionaryEncoding {
    DictionaryKind dictionaryKind_;
    int64_t id_;
    std::optional<Int> indexType_;
    bool isOrdered_;

    DictionaryEncoding();
    DictionaryEncoding(const ::DictionaryEncoding *root);
    DictionaryEncoding(const std::vector<uint8_t> &bytes);
};

struct Field {
    std::optional<std::vector<Field>> children_;
    std::optional<std::vector<KeyValue>> custom_metadata_;
    std::optional<DictionaryEncoding> dictionary_;
    std::optional<std::string> name_;
    bool nullable_;
    std::optional<Type> type_;

    Field();
    Field(const ::Field *root);
    Field(const std::vector<uint8_t> &bytes);
};

struct KeyValue {
    std::optional<std::string> key_;
    std::optional<std::string> value_;

    KeyValue();
    KeyValue(const ::KeyValue *root);
    KeyValue(const std::vector<uint8_t> &bytes);
};

struct Schema {
    std::optional<std::vector<KeyValue>> custom_metadata_;
    Endianness endianness_;
    std::optional<std::vector<Feature>> features_;
    std::optional<std::vector<Field>> fields_;

    Schema();
    Schema(const ::Schema *root);
    Schema(const std::vector<uint8_t> &bytes);
};

std::pair<::flatbuffers::Offset<void>, ::Type>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Type &o);
::flatbuffers::Offset<::Null>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Null &);

::flatbuffers::Offset<::Int>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Int &);

::flatbuffers::Offset<::FloatingPoint>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const FloatingPoint &);

::flatbuffers::Offset<::Binary>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Binary &);

::flatbuffers::Offset<::Utf8>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Utf8 &);

::flatbuffers::Offset<::Bool>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Bool &);

::flatbuffers::Offset<::Decimal>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Decimal &);

::flatbuffers::Offset<::Date>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Date &);

::flatbuffers::Offset<::Time>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Time &);

::flatbuffers::Offset<::Timestamp>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Timestamp &);

::flatbuffers::Offset<::Interval>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Interval &);

::flatbuffers::Offset<::List>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const List &);

::flatbuffers::Offset<::Struct_>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Struct_ &);

::flatbuffers::Offset<::Union>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Union &);

::flatbuffers::Offset<::FixedSizeBinary>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const FixedSizeBinary &);

::flatbuffers::Offset<::FixedSizeList>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const FixedSizeList &);

::flatbuffers::Offset<::Map>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Map &);

::flatbuffers::Offset<::Duration>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Duration &);

::flatbuffers::Offset<::LargeBinary>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const LargeBinary &);

::flatbuffers::Offset<::LargeUtf8>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const LargeUtf8 &);

::flatbuffers::Offset<::LargeList>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const LargeList &);

::flatbuffers::Offset<::DictionaryEncoding>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const DictionaryEncoding &);

::flatbuffers::Offset<::Field>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Field &);

::flatbuffers::Offset<::KeyValue>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const KeyValue &);

::flatbuffers::Offset<::Schema>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Schema &);


std::vector<uint8_t>
to_bytes(const Null &o);

std::vector<uint8_t>
to_bytes(const Int &o);

std::vector<uint8_t>
to_bytes(const FloatingPoint &o);

std::vector<uint8_t>
to_bytes(const Binary &o);

std::vector<uint8_t>
to_bytes(const Utf8 &o);

std::vector<uint8_t>
to_bytes(const Bool &o);

std::vector<uint8_t>
to_bytes(const Decimal &o);

std::vector<uint8_t>
to_bytes(const Date &o);

std::vector<uint8_t>
to_bytes(const Time &o);

std::vector<uint8_t>
to_bytes(const Timestamp &o);

std::vector<uint8_t>
to_bytes(const Interval &o);

std::vector<uint8_t>
to_bytes(const List &o);

std::vector<uint8_t>
to_bytes(const Struct_ &o);

std::vector<uint8_t>
to_bytes(const Union &o);

std::vector<uint8_t>
to_bytes(const FixedSizeBinary &o);

std::vector<uint8_t>
to_bytes(const FixedSizeList &o);

std::vector<uint8_t>
to_bytes(const Map &o);

std::vector<uint8_t>
to_bytes(const Duration &o);

std::vector<uint8_t>
to_bytes(const LargeBinary &o);

std::vector<uint8_t>
to_bytes(const LargeUtf8 &o);

std::vector<uint8_t>
to_bytes(const LargeList &o);

std::vector<uint8_t>
to_bytes(const DictionaryEncoding &o);

std::vector<uint8_t>
to_bytes(const Field &o);

std::vector<uint8_t>
to_bytes(const KeyValue &o);

std::vector<uint8_t>
to_bytes(const Schema &o);


} // namespace types
} // namespace ul