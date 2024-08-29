// Copyright (c), CommunityLogiq Software
// 
// THIS FILE IS AUTOGENERATED, DO NOT EDIT

#pragma once

#include <optional>

#include "ulsdk/external/json.h"
#include "ulsdk/request_context.h"
#include "ulsdk/ulsdk.h"

struct json_value_s;


namespace ul {
namespace api {
namespace gate {

struct AdUser {
    std::string display_name_;
    std::string id_;
    std::string user_principal_name_;
    std::vector<std::string> other_mails_;
    std::optional<std::string> department_;
    std::string created_date_time_;

    AdUser() = default;
    AdUser(const struct json_value_s *root);
};

std::vector<uint8_t>
to_bytes(const AdUser &o);

struct AdGroup {
    std::string id_;
    std::string display_name_;
    std::optional<std::string> description_;

    AdGroup() = default;
    AdGroup(const struct json_value_s *root);
};

std::vector<uint8_t>
to_bytes(const AdGroup &o);

struct Bootstrap {
    AdUser user_;
    std::vector<AdGroup> groups_;
    std::vector<AdGroup> v_2groups_;
    struct json_value_s * client_secrets_;

    ~Bootstrap() {
        std::free((void *)client_secrets_);
    }

    Bootstrap(const Bootstrap &o)
        : user_(o.user_)
        , groups_(o.groups_)
        , v_2groups_(o.v_2groups_) {
        client_secrets_ = json_extract_value(o.client_secrets_);
    }

    Bootstrap(Bootstrap &&o)
        : user_(std::move(o.user_))
        , groups_(std::move(o.groups_))
        , v_2groups_(std::move(o.v_2groups_)) {
        client_secrets_ = o.client_secrets_;
        o.client_secrets_ = nullptr;
    }

    Bootstrap() = default;
    Bootstrap(const struct json_value_s *root);
};

std::vector<uint8_t>
to_bytes(const Bootstrap &o);

/**
 * Retrieves the current user's details, groups they belong to, and secrets that are only available when authenticated.
 * @return The current user details needed to start the UrbanLogiq web application.
 */
Result<Bootstrap>
bootstrap(
    ul::RequestContext &ctx
);

} // namespace gate
} // namespace api
} // namespace ul
