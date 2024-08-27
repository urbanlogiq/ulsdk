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
///
/// ----------------------------------------------------------------------
/// Top-level Type value, enabling extensible type-specific metadata. We can
/// add new logical types to Type without breaking backwards compatibility
///
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
///
/// These are stored in the flatbuffer in the Type union below
///
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

///
/// Opaque binary data
///
struct Binary {

    Binary();
    Binary(const ::Binary *root);
    Binary(const std::vector<uint8_t> &bytes);
};

///
/// Unicode with UTF-8 encoding
///
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

///
/// Exact decimal value represented as an integer value in two's
/// complement. Currently only 128-bit (16-byte) and 256-bit (32-byte) integers
/// are used. The representation uses the endianness indicated
/// in the Schema.
///
struct Decimal {
    int32_t bitWidth_;
    int32_t precision_;
    int32_t scale_;

    Decimal();
    Decimal(const ::Decimal *root);
    Decimal(const std::vector<uint8_t> &bytes);
};

///
/// Date is either a 32-bit or 64-bit signed integer type representing an
/// elapsed time since UNIX epoch (1970-01-01), stored in either of two units:
///
/// * Milliseconds (64 bits) indicating UNIX time elapsed since the epoch (no
///   leap seconds), where the values are evenly divisible by 86400000
/// * Days (32 bits) since the UNIX epoch
///
struct Date {
    DateUnit unit_;

    Date();
    Date(const ::Date *root);
    Date(const std::vector<uint8_t> &bytes);
};

///
/// Time is either a 32-bit or 64-bit signed integer type representing an
/// elapsed time since midnight, stored in either of four units: seconds,
/// milliseconds, microseconds or nanoseconds.
///
/// The integer `bitWidth` depends on the `unit` and must be one of the following:
/// * SECOND and MILLISECOND: 32 bits
/// * MICROSECOND and NANOSECOND: 64 bits
///
/// The allowed values are between 0 (inclusive) and 86400 (=24*60*60) seconds
/// (exclusive), adjusted for the time unit (for example, up to 86400000
/// exclusive for the MILLISECOND unit).
/// This definition doesn't allow for leap seconds. Time values from
/// measurements with leap seconds will need to be corrected when ingesting
/// into Arrow (for example by replacing the value 86400 with 86399).
///
struct Time {
    int32_t bitWidth_;
    TimeUnit unit_;

    Time();
    Time(const ::Time *root);
    Time(const std::vector<uint8_t> &bytes);
};

///
/// Timestamp is a 64-bit signed integer representing an elapsed time since a
/// fixed epoch, stored in either of four units: seconds, milliseconds,
/// microseconds or nanoseconds, and is optionally annotated with a timezone.
///
/// Timestamp values do not include any leap seconds (in other words, all
/// days are considered 86400 seconds long).
///
/// Timestamps with a non-empty timezone
/// ------------------------------------
///
/// If a Timestamp column has a non-empty timezone value, its epoch is
/// 1970-01-01 00:00:00 (January 1st 1970, midnight) in the *UTC* timezone
/// (the Unix epoch), regardless of the Timestamp's own timezone.
///
/// Therefore, timestamp values with a non-empty timezone correspond to
/// physical points in time together with some additional information about
/// how the data was obtained and/or how to display it (the timezone).
///
///   For example, the timestamp value 0 with the timezone string "Europe/Paris"
///   corresponds to "January 1st 1970, 00h00" in the UTC timezone, but the
///   application may prefer to display it as "January 1st 1970, 01h00" in
///   the Europe/Paris timezone (which is the same physical point in time).
///
/// One consequence is that timestamp values with a non-empty timezone
/// can be compared and ordered directly, since they all share the same
/// well-known point of reference (the Unix epoch).
///
/// Timestamps with an unset / empty timezone
/// -----------------------------------------
///
/// If a Timestamp column has no timezone value, its epoch is
/// 1970-01-01 00:00:00 (January 1st 1970, midnight) in an *unknown* timezone.
///
/// Therefore, timestamp values without a timezone cannot be meaningfully
/// interpreted as physical points in time, but only as calendar / clock
/// indications ("wall clock time") in an unspecified timezone.
///
///   For example, the timestamp value 0 with an empty timezone string
///   corresponds to "January 1st 1970, 00h00" in an unknown timezone: there
///   is not enough information to interpret it as a well-defined physical
///   point in time.
///
/// One consequence is that timestamp values without a timezone cannot
/// be reliably compared or ordered, since they may have different points of
/// reference.  In particular, it is *not* possible to interpret an unset
/// or empty timezone as the same as "UTC".
///
/// Conversion between timezones
/// ----------------------------
///
/// If a Timestamp column has a non-empty timezone, changing the timezone
/// to a different non-empty value is a metadata-only operation:
/// the timestamp values need not change as their point of reference remains
/// the same (the Unix epoch).
///
/// However, if a Timestamp column has no timezone value, changing it to a
/// non-empty value requires to think about the desired semantics.
/// One possibility is to assume that the original timestamp values are
/// relative to the epoch of the timezone being set; timestamp values should
/// then adjusted to the Unix epoch (for example, changing the timezone from
/// empty to "Europe/Paris" would require converting the timestamp values
/// from "Europe/Paris" to "UTC", which seems counter-intuitive but is
/// nevertheless correct).
///
/// Guidelines for encoding data from external libraries
/// ----------------------------------------------------
///
/// Date & time libraries often have multiple different data types for temporal
/// data. In order to ease interoperability between different implementations the
/// Arrow project has some recommendations for encoding these types into a Timestamp
/// column.
///
/// An "instant" represents a physical point in time that has no relevant timezone
/// (for example, astronomical data). To encode an instant, use a Timestamp with
/// the timezone string set to "UTC", and make sure the Timestamp values
/// are relative to the UTC epoch (January 1st 1970, midnight).
///
/// A "zoned date-time" represents a physical point in time annotated with an
/// informative timezone (for example, the timezone in which the data was
/// recorded).  To encode a zoned date-time, use a Timestamp with the timezone
/// string set to the name of the timezone, and make sure the Timestamp values
/// are relative to the UTC epoch (January 1st 1970, midnight).
///
///  (There is some ambiguity between an instant and a zoned date-time with the
///   UTC timezone.  Both of these are stored the same in Arrow.  Typically,
///   this distinction does not matter.  If it does, then an application should
///   use custom metadata or an extension type to distinguish between the two cases.)
///
/// An "offset date-time" represents a physical point in time combined with an
/// explicit offset from UTC.  To encode an offset date-time, use a Timestamp
/// with the timezone string set to the numeric timezone offset string
/// (e.g. "+03:00"), and make sure the Timestamp values are relative to
/// the UTC epoch (January 1st 1970, midnight).
///
/// A "naive date-time" (also called "local date-time" in some libraries)
/// represents a wall clock time combined with a calendar date, but with
/// no indication of how to map this information to a physical point in time.
/// Naive date-times must be handled with care because of this missing
/// information, and also because daylight saving time (DST) may make
/// some values ambiguous or non-existent. A naive date-time may be
/// stored as a struct with Date and Time fields. However, it may also be
/// encoded into a Timestamp column with an empty timezone. The timestamp
/// values should be computed "as if" the timezone of the date-time values
/// was UTC; for example, the naive date-time "January 1st 1970, 00h00" would
/// be encoded as timestamp value 0.
///
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

///
/// A Struct_ in the flatbuffer metadata is the same as an Arrow Struct
/// (according to the physical memory layout). We used Struct_ here as
/// Struct is a reserved word in Flatbuffers
///
struct Struct_ {

    Struct_();
    Struct_(const ::Struct_ *root);
    Struct_(const std::vector<uint8_t> &bytes);
};

///
/// A union is a complex type with children in Field
/// By default ids in the type vector refer to the offsets in the children
/// optionally typeIds provides an indirection between the child offset and the type id
/// for each child `typeIds[offset]` is the id used in the type vector
///
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

///
/// A Map is a logical nested type that is represented as
///
/// List<entries: Struct<key: K, value: V>>
///
/// In this layout, the keys and values are each respectively contiguous. We do
/// not constrain the key and value types, so the application is responsible
/// for ensuring that the keys are hashable and unique. Whether the keys are sorted
/// may be set in the metadata for this field.
///
/// In a field with Map type, the field has a child Struct field, which then
/// has two children: key type and the second the value type. The names of the
/// child fields may be respectively "entries", "key", and "value", but this is
/// not enforced.
///
/// Map
/// ```text
///   - child[0] entries: Struct
///     - child[0] key: K
///     - child[1] value: V
/// ```
/// Neither the "entries" field nor the "key" field may be nullable.
///
/// The metadata is structured so that Arrow systems without special handling
/// for Map can make Map an alias for List. The "layout" attribute for the Map
/// field must have the same contents as a List.
///
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

///
/// Same as Binary, but with 64-bit offsets, allowing to represent
/// extremely large data values.
///
struct LargeBinary {

    LargeBinary();
    LargeBinary(const ::LargeBinary *root);
    LargeBinary(const std::vector<uint8_t> &bytes);
};

///
/// Same as Utf8, but with 64-bit offsets, allowing to represent
/// extremely large data values.
///
struct LargeUtf8 {

    LargeUtf8();
    LargeUtf8(const ::LargeUtf8 *root);
    LargeUtf8(const std::vector<uint8_t> &bytes);
};

///
/// Same as List, but with 64-bit offsets, allowing to represent
/// extremely large data values.
///
struct LargeList {

    LargeList();
    LargeList(const ::LargeList *root);
    LargeList(const std::vector<uint8_t> &bytes);
};

///
/// ----------------------------------------------------------------------
/// A Buffer represents a single contiguous memory segment
///
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

///
/// ----------------------------------------------------------------------
/// A field represents a named column in a record / row batch or child of a
/// nested type.
///
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

///
/// ----------------------------------------------------------------------
/// user defined key value pairs to add custom metadata to arrow
/// key namespacing is the responsibility of the user
///
struct KeyValue {
    std::optional<std::string> key_;
    std::optional<std::string> value_;

    KeyValue();
    KeyValue(const ::KeyValue *root);
    KeyValue(const std::vector<uint8_t> &bytes);
};

///
/// ----------------------------------------------------------------------
/// A Schema describes the columns in a row batch
///
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
