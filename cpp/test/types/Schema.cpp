// Copyright (c), CommunityLogiq Software
// 
// THIS FILE IS AUTOGENERATED, DO NOT EDIT

#include "ulsdk/types/Schema.h"

#include "test.h"

bool
test_binary() {
    ::ul::types::Binary t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Binary deserialized = ::ul::types::Binary(bytes);
    return true;
}

TypeTest test_binary_obj(test_binary, "Binary");

bool
test_bool() {
    ::ul::types::Bool t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Bool deserialized = ::ul::types::Bool(bytes);
    return true;
}

TypeTest test_bool_obj(test_bool, "Bool");

bool
test_date() {
    ::ul::types::Date t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Date deserialized = ::ul::types::Date(bytes);
    return true;
}

TypeTest test_date_obj(test_date, "Date");

bool
test_decimal() {
    ::ul::types::Decimal t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Decimal deserialized = ::ul::types::Decimal(bytes);
    return true;
}

TypeTest test_decimal_obj(test_decimal, "Decimal");

bool
test_dictionary_encoding() {
    ::ul::types::DictionaryEncoding t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::DictionaryEncoding deserialized = ::ul::types::DictionaryEncoding(bytes);
    return true;
}

TypeTest test_dictionary_encoding_obj(test_dictionary_encoding, "DictionaryEncoding");

bool
test_duration() {
    ::ul::types::Duration t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Duration deserialized = ::ul::types::Duration(bytes);
    return true;
}

TypeTest test_duration_obj(test_duration, "Duration");

bool
test_field() {
    ::ul::types::Field t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Field deserialized = ::ul::types::Field(bytes);
    return true;
}

TypeTest test_field_obj(test_field, "Field");

bool
test_fixed_size_binary() {
    ::ul::types::FixedSizeBinary t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::FixedSizeBinary deserialized = ::ul::types::FixedSizeBinary(bytes);
    return true;
}

TypeTest test_fixed_size_binary_obj(test_fixed_size_binary, "FixedSizeBinary");

bool
test_fixed_size_list() {
    ::ul::types::FixedSizeList t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::FixedSizeList deserialized = ::ul::types::FixedSizeList(bytes);
    return true;
}

TypeTest test_fixed_size_list_obj(test_fixed_size_list, "FixedSizeList");

bool
test_floating_point() {
    ::ul::types::FloatingPoint t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::FloatingPoint deserialized = ::ul::types::FloatingPoint(bytes);
    return true;
}

TypeTest test_floating_point_obj(test_floating_point, "FloatingPoint");

bool
test_int() {
    ::ul::types::Int t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Int deserialized = ::ul::types::Int(bytes);
    return true;
}

TypeTest test_int_obj(test_int, "Int");

bool
test_interval() {
    ::ul::types::Interval t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Interval deserialized = ::ul::types::Interval(bytes);
    return true;
}

TypeTest test_interval_obj(test_interval, "Interval");

bool
test_key_value() {
    ::ul::types::KeyValue t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::KeyValue deserialized = ::ul::types::KeyValue(bytes);
    return true;
}

TypeTest test_key_value_obj(test_key_value, "KeyValue");

bool
test_large_binary() {
    ::ul::types::LargeBinary t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::LargeBinary deserialized = ::ul::types::LargeBinary(bytes);
    return true;
}

TypeTest test_large_binary_obj(test_large_binary, "LargeBinary");

bool
test_large_list() {
    ::ul::types::LargeList t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::LargeList deserialized = ::ul::types::LargeList(bytes);
    return true;
}

TypeTest test_large_list_obj(test_large_list, "LargeList");

bool
test_large_utf_8() {
    ::ul::types::LargeUtf8 t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::LargeUtf8 deserialized = ::ul::types::LargeUtf8(bytes);
    return true;
}

TypeTest test_large_utf_8_obj(test_large_utf_8, "LargeUtf8");

bool
test_list() {
    ::ul::types::List t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::List deserialized = ::ul::types::List(bytes);
    return true;
}

TypeTest test_list_obj(test_list, "List");

bool
test_map() {
    ::ul::types::Map t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Map deserialized = ::ul::types::Map(bytes);
    return true;
}

TypeTest test_map_obj(test_map, "Map");

bool
test_null() {
    ::ul::types::Null t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Null deserialized = ::ul::types::Null(bytes);
    return true;
}

TypeTest test_null_obj(test_null, "Null");

bool
test_schema() {
    ::ul::types::Schema t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Schema deserialized = ::ul::types::Schema(bytes);
    return true;
}

TypeTest test_schema_obj(test_schema, "Schema");

bool
test_struct() {
    ::ul::types::Struct_ t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Struct_ deserialized = ::ul::types::Struct_(bytes);
    return true;
}

TypeTest test_struct_obj(test_struct, "Struct_");

bool
test_time() {
    ::ul::types::Time t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Time deserialized = ::ul::types::Time(bytes);
    return true;
}

TypeTest test_time_obj(test_time, "Time");

bool
test_timestamp() {
    ::ul::types::Timestamp t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Timestamp deserialized = ::ul::types::Timestamp(bytes);
    return true;
}

TypeTest test_timestamp_obj(test_timestamp, "Timestamp");

bool
test_union() {
    ::ul::types::Union t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Union deserialized = ::ul::types::Union(bytes);
    return true;
}

TypeTest test_union_obj(test_union, "Union");

bool
test_utf_8() {
    ::ul::types::Utf8 t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Utf8 deserialized = ::ul::types::Utf8(bytes);
    return true;
}

TypeTest test_utf_8_obj(test_utf_8, "Utf8");
