// Copyright (c), CommunityLogiq Software
// 
// THIS FILE IS AUTOGENERATED, DO NOT EDIT

#include "ulsdk/types/value.h"

#include "test.h"

bool
test_v_array() {
    ::ul::types::VArray t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VArray deserialized = ::ul::types::VArray(bytes);
    return true;
}

TypeTest test_v_array_obj(test_v_array, "VArray");

bool
test_v_bool() {
    ::ul::types::VBool t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VBool deserialized = ::ul::types::VBool(bytes);
    return true;
}

TypeTest test_v_bool_obj(test_v_bool, "VBool");

bool
test_v_bytes() {
    ::ul::types::VBytes t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VBytes deserialized = ::ul::types::VBytes(bytes);
    return true;
}

TypeTest test_v_bytes_obj(test_v_bytes, "VBytes");

bool
test_v_char() {
    ::ul::types::VChar t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VChar deserialized = ::ul::types::VChar(bytes);
    return true;
}

TypeTest test_v_char_obj(test_v_char, "VChar");

bool
test_vf32() {
    ::ul::types::VF32 t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VF32 deserialized = ::ul::types::VF32(bytes);
    return true;
}

TypeTest test_vf32_obj(test_vf32, "VF32");

bool
test_vf64() {
    ::ul::types::VF64 t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VF64 deserialized = ::ul::types::VF64(bytes);
    return true;
}

TypeTest test_vf64_obj(test_vf64, "VF64");

bool
test_v_fixed_size_bytes() {
    ::ul::types::VFixedSizeBytes t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VFixedSizeBytes deserialized = ::ul::types::VFixedSizeBytes(bytes);
    return true;
}

TypeTest test_v_fixed_size_bytes_obj(test_v_fixed_size_bytes, "VFixedSizeBytes");

bool
test_vi16() {
    ::ul::types::VI16 t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VI16 deserialized = ::ul::types::VI16(bytes);
    return true;
}

TypeTest test_vi16_obj(test_vi16, "VI16");

bool
test_vi32() {
    ::ul::types::VI32 t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VI32 deserialized = ::ul::types::VI32(bytes);
    return true;
}

TypeTest test_vi32_obj(test_vi32, "VI32");

bool
test_vi64() {
    ::ul::types::VI64 t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VI64 deserialized = ::ul::types::VI64(bytes);
    return true;
}

TypeTest test_vi64_obj(test_vi64, "VI64");

bool
test_vi8() {
    ::ul::types::VI8 t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VI8 deserialized = ::ul::types::VI8(bytes);
    return true;
}

TypeTest test_vi8_obj(test_vi8, "VI8");

bool
test_v_isize() {
    ::ul::types::VIsize t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VIsize deserialized = ::ul::types::VIsize(bytes);
    return true;
}

TypeTest test_v_isize_obj(test_v_isize, "VIsize");

bool
test_v_null() {
    ::ul::types::VNull t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VNull deserialized = ::ul::types::VNull(bytes);
    return true;
}

TypeTest test_v_null_obj(test_v_null, "VNull");

bool
test_v_str() {
    ::ul::types::VStr t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VStr deserialized = ::ul::types::VStr(bytes);
    return true;
}

TypeTest test_v_str_obj(test_v_str, "VStr");

bool
test_v_timestamp_ms() {
    ::ul::types::VTimestampMs t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VTimestampMs deserialized = ::ul::types::VTimestampMs(bytes);
    return true;
}

TypeTest test_v_timestamp_ms_obj(test_v_timestamp_ms, "VTimestampMs");

bool
test_v_timestamp_ms_utc() {
    ::ul::types::VTimestampMsUtc t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VTimestampMsUtc deserialized = ::ul::types::VTimestampMsUtc(bytes);
    return true;
}

TypeTest test_v_timestamp_ms_utc_obj(test_v_timestamp_ms_utc, "VTimestampMsUtc");

bool
test_v_timestamp_ns() {
    ::ul::types::VTimestampNs t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VTimestampNs deserialized = ::ul::types::VTimestampNs(bytes);
    return true;
}

TypeTest test_v_timestamp_ns_obj(test_v_timestamp_ns, "VTimestampNs");

bool
test_v_timestamp_ns_utc() {
    ::ul::types::VTimestampNsUtc t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VTimestampNsUtc deserialized = ::ul::types::VTimestampNsUtc(bytes);
    return true;
}

TypeTest test_v_timestamp_ns_utc_obj(test_v_timestamp_ns_utc, "VTimestampNsUtc");

bool
test_v_tri_2d() {
    ::ul::types::VTri2D t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VTri2D deserialized = ::ul::types::VTri2D(bytes);
    return true;
}

TypeTest test_v_tri_2d_obj(test_v_tri_2d, "VTri2D");

bool
test_vu16() {
    ::ul::types::VU16 t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VU16 deserialized = ::ul::types::VU16(bytes);
    return true;
}

TypeTest test_vu16_obj(test_vu16, "VU16");

bool
test_vu32() {
    ::ul::types::VU32 t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VU32 deserialized = ::ul::types::VU32(bytes);
    return true;
}

TypeTest test_vu32_obj(test_vu32, "VU32");

bool
test_vu64() {
    ::ul::types::VU64 t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VU64 deserialized = ::ul::types::VU64(bytes);
    return true;
}

TypeTest test_vu64_obj(test_vu64, "VU64");

bool
test_vu8() {
    ::ul::types::VU8 t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VU8 deserialized = ::ul::types::VU8(bytes);
    return true;
}

TypeTest test_vu8_obj(test_vu8, "VU8");

bool
test_v_unit() {
    ::ul::types::VUnit t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VUnit deserialized = ::ul::types::VUnit(bytes);
    return true;
}

TypeTest test_v_unit_obj(test_v_unit, "VUnit");

bool
test_v_usize() {
    ::ul::types::VUsize t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::VUsize deserialized = ::ul::types::VUsize(bytes);
    return true;
}

TypeTest test_v_usize_obj(test_v_usize, "VUsize");

bool
test_value_instance() {
    ::ul::types::ValueInstance t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::ValueInstance deserialized = ::ul::types::ValueInstance(bytes);
    return true;
}

TypeTest test_value_instance_obj(test_value_instance, "ValueInstance");