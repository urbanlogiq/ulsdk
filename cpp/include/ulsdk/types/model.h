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
#include "ulsdk/types/id.h"
#include "ulsdk/types/generated/model_generated.h"

namespace ul {
namespace types {

struct Model;

struct Model {
    ObjectId location_;
    std::string name_;
    std::optional<std::string> source_;

    Model();
    Model(const ::Model *root);
    Model(const std::vector<uint8_t> &bytes);
};

::flatbuffers::Offset<::Model>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Model &);


std::vector<uint8_t>
to_bytes(const Model &o);


} // namespace types
} // namespace ul