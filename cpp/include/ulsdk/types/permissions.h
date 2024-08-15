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
#include "ulsdk/types/generated/permissions_generated.h"

namespace ul {
namespace types {

struct AccessControlList;
struct Role;

using ::PermissionTy;
struct AccessControlList {
    std::optional<ObjectId> extends_;
    std::vector<Role> roles_;

    AccessControlList();
    AccessControlList(const ::AccessControlList *root);
    AccessControlList(const std::vector<uint8_t> &bytes);
};

struct Role {
    uint32_t permission_;
    B2cId principal_;

    Role();
    Role(const ::Role *root);
    Role(const std::vector<uint8_t> &bytes);
};

::flatbuffers::Offset<::AccessControlList>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const AccessControlList &);

::flatbuffers::Offset<::Role>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Role &);


std::vector<uint8_t>
to_bytes(const AccessControlList &o);

std::vector<uint8_t>
to_bytes(const Role &o);


} // namespace types
} // namespace ul
