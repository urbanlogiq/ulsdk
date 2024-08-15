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
#include "ulsdk/types/generated/value_generated.h"

namespace ul {
namespace types {

struct Point2D;
struct Tri2D;
struct VArray;
struct VBool;
struct VBytes;
struct VChar;
struct VF32;
struct VF64;
struct VFixedSizeBytes;
struct VI16;
struct VI32;
struct VI64;
struct VI8;
struct VIsize;
struct VNull;
struct VStr;
struct VTimestampMs;
struct VTimestampMsUtc;
struct VTimestampNs;
struct VTimestampNsUtc;
struct VTri2D;
struct VU16;
struct VU32;
struct VU64;
struct VU8;
struct VUnit;
struct VUsize;
struct ValueInstance;

typedef std::variant<
    std::shared_ptr<VBool>,
    std::shared_ptr<VUnit>,
    std::shared_ptr<VChar>,
    std::shared_ptr<VNull>,
    std::shared_ptr<VI8>,
    std::shared_ptr<VU8>,
    std::shared_ptr<VI16>,
    std::shared_ptr<VU16>,
    std::shared_ptr<VI32>,
    std::shared_ptr<VU32>,
    std::shared_ptr<VF32>,
    std::shared_ptr<VIsize>,
    std::shared_ptr<VUsize>,
    std::shared_ptr<VI64>,
    std::shared_ptr<VU64>,
    std::shared_ptr<VF64>,
    std::shared_ptr<VStr>,
    std::shared_ptr<VBytes>,
    std::shared_ptr<VArray>,
    std::shared_ptr<VTri2D>,
    std::shared_ptr<VFixedSizeBytes>,
    std::shared_ptr<VTimestampMsUtc>,
    std::shared_ptr<VTimestampMs>,
    std::shared_ptr<VTimestampNsUtc>,
    std::shared_ptr<VTimestampNs>
> Value;

using ::ValueTy;
struct VBool {
    bool v_;

    VBool();
    VBool(const ::VBool *root);
    VBool(const std::vector<uint8_t> &bytes);
};

struct VUnit {

    VUnit();
    VUnit(const ::VUnit *root);
    VUnit(const std::vector<uint8_t> &bytes);
};

struct VChar {
    uint32_t v_;

    VChar();
    VChar(const ::VChar *root);
    VChar(const std::vector<uint8_t> &bytes);
};

struct VNull {

    VNull();
    VNull(const ::VNull *root);
    VNull(const std::vector<uint8_t> &bytes);
};

struct VI8 {
    int8_t v_;

    VI8();
    VI8(const ::VI8 *root);
    VI8(const std::vector<uint8_t> &bytes);
};

struct VU8 {
    uint8_t v_;

    VU8();
    VU8(const ::VU8 *root);
    VU8(const std::vector<uint8_t> &bytes);
};

struct VI16 {
    int16_t v_;

    VI16();
    VI16(const ::VI16 *root);
    VI16(const std::vector<uint8_t> &bytes);
};

struct VU16 {
    uint16_t v_;

    VU16();
    VU16(const ::VU16 *root);
    VU16(const std::vector<uint8_t> &bytes);
};

struct VI32 {
    int32_t v_;

    VI32();
    VI32(const ::VI32 *root);
    VI32(const std::vector<uint8_t> &bytes);
};

struct VU32 {
    uint32_t v_;

    VU32();
    VU32(const ::VU32 *root);
    VU32(const std::vector<uint8_t> &bytes);
};

struct VF32 {
    float v_;

    VF32();
    VF32(const ::VF32 *root);
    VF32(const std::vector<uint8_t> &bytes);
};

struct VIsize {
    int64_t v_;

    VIsize();
    VIsize(const ::VIsize *root);
    VIsize(const std::vector<uint8_t> &bytes);
};

struct VUsize {
    uint64_t v_;

    VUsize();
    VUsize(const ::VUsize *root);
    VUsize(const std::vector<uint8_t> &bytes);
};

struct VI64 {
    int64_t v_;

    VI64();
    VI64(const ::VI64 *root);
    VI64(const std::vector<uint8_t> &bytes);
};

struct VU64 {
    uint64_t v_;

    VU64();
    VU64(const ::VU64 *root);
    VU64(const std::vector<uint8_t> &bytes);
};

struct VF64 {
    double v_;

    VF64();
    VF64(const ::VF64 *root);
    VF64(const std::vector<uint8_t> &bytes);
};

struct VStr {
    std::string v_;

    VStr();
    VStr(const ::VStr *root);
    VStr(const std::vector<uint8_t> &bytes);
};

struct VBytes {
    std::vector<uint8_t> v_;

    VBytes();
    VBytes(const ::VBytes *root);
    VBytes(const std::vector<uint8_t> &bytes);
};

struct VArray {
    std::vector<ValueInstance> v_;

    VArray();
    VArray(const ::VArray *root);
    VArray(const std::vector<uint8_t> &bytes);
};

struct Point2D {
    float x_;
    float y_;

    Point2D();
    Point2D(const ::Point2D *root);
};

struct Tri2D {
    std::optional<Point2D> p0_;
    std::optional<Point2D> p1_;
    std::optional<Point2D> p2_;

    Tri2D();
    Tri2D(const ::Tri2D *root);
};

struct VTri2D {
    Tri2D v_;

    VTri2D();
    VTri2D(const ::VTri2D *root);
    VTri2D(const std::vector<uint8_t> &bytes);
};

struct VFixedSizeBytes {
    int32_t sz_;
    std::vector<uint8_t> v_;

    VFixedSizeBytes();
    VFixedSizeBytes(const ::VFixedSizeBytes *root);
    VFixedSizeBytes(const std::vector<uint8_t> &bytes);
};

struct VTimestampMsUtc {
    int64_t v_;

    VTimestampMsUtc();
    VTimestampMsUtc(const ::VTimestampMsUtc *root);
    VTimestampMsUtc(const std::vector<uint8_t> &bytes);
};

struct VTimestampMs {
    int64_t v_;

    VTimestampMs();
    VTimestampMs(const ::VTimestampMs *root);
    VTimestampMs(const std::vector<uint8_t> &bytes);
};

struct VTimestampNsUtc {
    int64_t v_;

    VTimestampNsUtc();
    VTimestampNsUtc(const ::VTimestampNsUtc *root);
    VTimestampNsUtc(const std::vector<uint8_t> &bytes);
};

struct VTimestampNs {
    int64_t v_;

    VTimestampNs();
    VTimestampNs(const ::VTimestampNs *root);
    VTimestampNs(const std::vector<uint8_t> &bytes);
};

struct ValueInstance {
    Value v_;

    ValueInstance();
    ValueInstance(const ::ValueInstance *root);
    ValueInstance(const std::vector<uint8_t> &bytes);
};

std::pair<::flatbuffers::Offset<void>, ::Value>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Value &o);
::flatbuffers::Offset<::VBool>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VBool &);

::flatbuffers::Offset<::VUnit>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VUnit &);

::flatbuffers::Offset<::VChar>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VChar &);

::flatbuffers::Offset<::VNull>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VNull &);

::flatbuffers::Offset<::VI8>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VI8 &);

::flatbuffers::Offset<::VU8>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VU8 &);

::flatbuffers::Offset<::VI16>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VI16 &);

::flatbuffers::Offset<::VU16>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VU16 &);

::flatbuffers::Offset<::VI32>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VI32 &);

::flatbuffers::Offset<::VU32>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VU32 &);

::flatbuffers::Offset<::VF32>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VF32 &);

::flatbuffers::Offset<::VIsize>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VIsize &);

::flatbuffers::Offset<::VUsize>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VUsize &);

::flatbuffers::Offset<::VI64>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VI64 &);

::flatbuffers::Offset<::VU64>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VU64 &);

::flatbuffers::Offset<::VF64>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VF64 &);

::flatbuffers::Offset<::VStr>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VStr &);

::flatbuffers::Offset<::VBytes>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VBytes &);

::flatbuffers::Offset<::VArray>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VArray &);

::flatbuffers::Offset<::VTri2D>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VTri2D &);

::flatbuffers::Offset<::VFixedSizeBytes>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VFixedSizeBytes &);

::flatbuffers::Offset<::VTimestampMsUtc>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VTimestampMsUtc &);

::flatbuffers::Offset<::VTimestampMs>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VTimestampMs &);

::flatbuffers::Offset<::VTimestampNsUtc>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VTimestampNsUtc &);

::flatbuffers::Offset<::VTimestampNs>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const VTimestampNs &);

::flatbuffers::Offset<::ValueInstance>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const ValueInstance &);


std::vector<uint8_t>
to_bytes(const VBool &o);

std::vector<uint8_t>
to_bytes(const VUnit &o);

std::vector<uint8_t>
to_bytes(const VChar &o);

std::vector<uint8_t>
to_bytes(const VNull &o);

std::vector<uint8_t>
to_bytes(const VI8 &o);

std::vector<uint8_t>
to_bytes(const VU8 &o);

std::vector<uint8_t>
to_bytes(const VI16 &o);

std::vector<uint8_t>
to_bytes(const VU16 &o);

std::vector<uint8_t>
to_bytes(const VI32 &o);

std::vector<uint8_t>
to_bytes(const VU32 &o);

std::vector<uint8_t>
to_bytes(const VF32 &o);

std::vector<uint8_t>
to_bytes(const VIsize &o);

std::vector<uint8_t>
to_bytes(const VUsize &o);

std::vector<uint8_t>
to_bytes(const VI64 &o);

std::vector<uint8_t>
to_bytes(const VU64 &o);

std::vector<uint8_t>
to_bytes(const VF64 &o);

std::vector<uint8_t>
to_bytes(const VStr &o);

std::vector<uint8_t>
to_bytes(const VBytes &o);

std::vector<uint8_t>
to_bytes(const VArray &o);

std::vector<uint8_t>
to_bytes(const VTri2D &o);

std::vector<uint8_t>
to_bytes(const VFixedSizeBytes &o);

std::vector<uint8_t>
to_bytes(const VTimestampMsUtc &o);

std::vector<uint8_t>
to_bytes(const VTimestampMs &o);

std::vector<uint8_t>
to_bytes(const VTimestampNsUtc &o);

std::vector<uint8_t>
to_bytes(const VTimestampNs &o);

std::vector<uint8_t>
to_bytes(const ValueInstance &o);


} // namespace types
} // namespace ul
