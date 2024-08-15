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
#include "ulsdk/types/entity.h"
#include "ulsdk/types/fun.h"
#include "ulsdk/types/graph.h"
#include "ulsdk/types/id.h"
#include "ulsdk/types/query.h"
#include "ulsdk/types/value.h"
#include "ulsdk/types/generated/usecase_generated.h"

namespace ul {
namespace types {

struct UseCase;
struct UseCaseInputPair;

typedef std::variant<
    std::shared_ptr<ObjectId>,
    std::shared_ptr<Schema>,
    std::shared_ptr<ParameterizedQuery>,
    std::shared_ptr<ValueInstance>
> UseCaseInput;

using ::UseCaseModule;
using ::UseCaseTy;
struct UseCase {
    std::optional<std::string> abbreviation_;
    std::optional<std::string> description_;
    std::optional<std::string> extended_description_;
    std::optional<std::string> extended_title_;
    std::vector<UseCaseInputPair> inputs_;
    UseCaseModule module_;
    std::string name_;
    std::optional<std::string> subtitle_;
    UseCaseTy ty_;

    UseCase();
    UseCase(const ::UseCase *root);
    UseCase(const std::vector<uint8_t> &bytes);
};

struct UseCaseInputPair {
    std::optional<UseCaseInput> input_;
    std::string name_;

    UseCaseInputPair();
    UseCaseInputPair(const ::UseCaseInputPair *root);
    UseCaseInputPair(const std::vector<uint8_t> &bytes);
};

std::pair<::flatbuffers::Offset<void>, ::UseCaseInput>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const UseCaseInput &o);
::flatbuffers::Offset<::UseCase>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const UseCase &);

::flatbuffers::Offset<::UseCaseInputPair>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const UseCaseInputPair &);


std::vector<uint8_t>
to_bytes(const UseCase &o);

std::vector<uint8_t>
to_bytes(const UseCaseInputPair &o);


} // namespace types
} // namespace ul
