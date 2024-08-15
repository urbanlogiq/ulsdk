// Copyright (c), CommunityLogiq Software

#pragma once

#include <sodium.h>

#include <array>
#include <string>
#include <vector>

#include "ulsdk/ulsdk.h"

namespace ul {
struct Key {
    Uuid user_id_;
    Region region_;
    std::string access_key_;
    std::vector<uint8_t> secret_key_;

    Key() = delete;
    Key(const Key& other) = default;
    Key(const std::string& user_id,
        Region region,
        const std::string& access_key,
        const std::string& secret_key);
    Key(const Uuid& user_id,
        Region region,
        const std::string& access_key,
        const std::vector<uint8_t>& secret_key);
};
}  // namespace ul
