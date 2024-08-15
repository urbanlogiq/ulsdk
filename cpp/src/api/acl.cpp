// Copyright (c), CommunityLogiq Software
// 
// THIS FILE IS AUTOGENERATED, DO NOT EDIT

#include <cassert>
#include <cstring>
#include <cstdlib>
#include <sstream>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif
#include <arrow/record_batch.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#ifdef __clang__
#pragma clang diagnostic pop
#endif
#include "ulsdk/ulsdk.h"
#include "ulsdk/external/json.h"
#include "ulsdk/api/acl.h"

namespace ul {
namespace api {
namespace acl {

Result<::ul::types::ObjectSummaryList>
new_acl(
    ul::RequestContext &ctx
) {
    std::string path = "/v1/api/ulv2/datacatalog/acl/";

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const std::vector<uint8_t> body;
    const Result<std::vector<uint8_t>> res = ctx.post(path, body, "text/plain", params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<::ul::types::ObjectSummaryList>(error);
    }
    return ::ul::types::ObjectSummaryList(std::get<std::vector<uint8_t>>(res));
}

Result<::ul::types::ObjectSummaryList>
new_from(
    ul::RequestContext &ctx,
    std::optional<Uuid> extends
) {
    std::string path = "/v1/api/ulv2/datacatalog/acl/";

    std::map<std::string, std::string> params;
    if (extends.has_value()) {
        const auto extends_value = extends.value();
        params["extends"] = extends_value.to_string();
    }

    std::map<std::string, std::string> headers;
    const std::vector<uint8_t> body;
    const Result<std::vector<uint8_t>> res = ctx.post(path, body, "text/plain", params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<::ul::types::ObjectSummaryList>(error);
    }
    return ::ul::types::ObjectSummaryList(std::get<std::vector<uint8_t>>(res));
}

Result<Void>
request(
    ul::RequestContext &ctx,
    const ::ul::types::AccessRequest &request
) {
    std::string path = "/v1/api/ulv2/datacatalog/acl/request";

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const std::vector<uint8_t> body = ::ul::types::to_bytes(request);
    const Result<std::vector<uint8_t>> res = ctx.post(path, body, "application/octet-stream", params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<Void>(error);
    }
    return Result<Void>();
}

Result<Void>
share(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to,
    int64_t permission_bits
) {
    std::string path = "/v1/api/ulv2/datacatalog/acl/share/:id/:to/:permission";
    const size_t id_idx = path.find(":id");
    path.replace(id_idx, 2, id.to_string());
    const size_t to_idx = path.find(":to");
    path.replace(to_idx, 2, to.to_string());
    const size_t permission_idx = path.find(":permission");
    path.replace(permission_idx, 2, std::to_string(permission_bits));

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const std::vector<uint8_t> body;
    const Result<std::vector<uint8_t>> res = ctx.post(path, body, "text/plain", params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<Void>(error);
    }
    return Result<Void>();
}

Result<Void>
share_with_details(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to,
    int64_t permission_bits,
    const ::ul::types::ShareDetails &share_details
) {
    std::string path = "/v1/api/ulv2/datacatalog/acl/share/:id/:to/:permission";
    const size_t id_idx = path.find(":id");
    path.replace(id_idx, 2, id.to_string());
    const size_t to_idx = path.find(":to");
    path.replace(to_idx, 2, to.to_string());
    const size_t permission_idx = path.find(":permission");
    path.replace(permission_idx, 2, std::to_string(permission_bits));

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const std::vector<uint8_t> body = ::ul::types::to_bytes(share_details);
    const Result<std::vector<uint8_t>> res = ctx.post(path, body, "application/octet-stream", params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<Void>(error);
    }
    return Result<Void>();
}

Result<Void>
share_all(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to
) {
    std::string path = "/v1/api/ulv2/datacatalog/acl/share/:id/:to";
    const size_t id_idx = path.find(":id");
    path.replace(id_idx, 2, id.to_string());
    const size_t to_idx = path.find(":to");
    path.replace(to_idx, 2, to.to_string());

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const std::vector<uint8_t> body;
    const Result<std::vector<uint8_t>> res = ctx.post(path, body, "text/plain", params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<Void>(error);
    }
    return Result<Void>();
}

Result<Void>
share_all_with_details(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to,
    const ::ul::types::ShareDetails &share_details
) {
    std::string path = "/v1/api/ulv2/datacatalog/acl/share/:id/:to";
    const size_t id_idx = path.find(":id");
    path.replace(id_idx, 2, id.to_string());
    const size_t to_idx = path.find(":to");
    path.replace(to_idx, 2, to.to_string());

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const std::vector<uint8_t> body = ::ul::types::to_bytes(share_details);
    const Result<std::vector<uint8_t>> res = ctx.post(path, body, "application/octet-stream", params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<Void>(error);
    }
    return Result<Void>();
}

Result<Void>
grant(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to,
    int64_t permission_bits
) {
    std::string path = "/v1/api/ulv2/datacatalog/acl/grant/:id/:to/:permission";
    const size_t id_idx = path.find(":id");
    path.replace(id_idx, 2, id.to_string());
    const size_t to_idx = path.find(":to");
    path.replace(to_idx, 2, to.to_string());
    const size_t permission_idx = path.find(":permission");
    path.replace(permission_idx, 2, std::to_string(permission_bits));

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const std::vector<uint8_t> body;
    const Result<std::vector<uint8_t>> res = ctx.post(path, body, "text/plain", params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<Void>(error);
    }
    return Result<Void>();
}

Result<Void>
grant_with_details(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to,
    int64_t permission_bits,
    const ::ul::types::ShareDetails &grant_details
) {
    std::string path = "/v1/api/ulv2/datacatalog/acl/grant/:id/:to/:permission";
    const size_t id_idx = path.find(":id");
    path.replace(id_idx, 2, id.to_string());
    const size_t to_idx = path.find(":to");
    path.replace(to_idx, 2, to.to_string());
    const size_t permission_idx = path.find(":permission");
    path.replace(permission_idx, 2, std::to_string(permission_bits));

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const std::vector<uint8_t> body = ::ul::types::to_bytes(grant_details);
    const Result<std::vector<uint8_t>> res = ctx.post(path, body, "application/octet-stream", params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<Void>(error);
    }
    return Result<Void>();
}

Result<Void>
grant_all(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to
) {
    std::string path = "/v1/api/ulv2/datacatalog/acl/grant/:id/:to";
    const size_t id_idx = path.find(":id");
    path.replace(id_idx, 2, id.to_string());
    const size_t to_idx = path.find(":to");
    path.replace(to_idx, 2, to.to_string());

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const std::vector<uint8_t> body;
    const Result<std::vector<uint8_t>> res = ctx.post(path, body, "text/plain", params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<Void>(error);
    }
    return Result<Void>();
}

Result<Void>
grant_all_with_details(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to,
    const ::ul::types::ShareDetails &grant_details
) {
    std::string path = "/v1/api/ulv2/datacatalog/acl/grant/:id/:to";
    const size_t id_idx = path.find(":id");
    path.replace(id_idx, 2, id.to_string());
    const size_t to_idx = path.find(":to");
    path.replace(to_idx, 2, to.to_string());

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const std::vector<uint8_t> body = ::ul::types::to_bytes(grant_details);
    const Result<std::vector<uint8_t>> res = ctx.post(path, body, "application/octet-stream", params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<Void>(error);
    }
    return Result<Void>();
}

Result<Void>
revoke(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &from
) {
    std::string path = "/v1/api/ulv2/datacatalog/acl/revoke/:id/:from";
    const size_t id_idx = path.find(":id");
    path.replace(id_idx, 2, id.to_string());
    const size_t from_idx = path.find(":from");
    path.replace(from_idx, 2, from.to_string());

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const std::vector<uint8_t> body;
    const Result<std::vector<uint8_t>> res = ctx.post(path, body, "text/plain", params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<Void>(error);
    }
    return Result<Void>();
}

Result<Void>
get_permissions(
    ul::RequestContext &ctx,
    const Uuid &id
) {
    std::string path = "/v1/api/ulv2/datacatalog/acl/perms/:id";
    const size_t id_idx = path.find(":id");
    path.replace(id_idx, 2, id.to_string());

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const Result<std::vector<uint8_t>> res = ctx.get(path, params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<Void>(error);
    }
    return Result<Void>();
}

Result<Void>
set(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &acl_id
) {
    std::string path = "/v1/api/ulv2/datacatalog/acl/set/:id/:acl_id";
    const size_t id_idx = path.find(":id");
    path.replace(id_idx, 2, id.to_string());
    const size_t acl_id_idx = path.find(":acl_id");
    path.replace(acl_id_idx, 2, acl_id.to_string());

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const std::vector<uint8_t> body;
    const Result<std::vector<uint8_t>> res = ctx.post(path, body, "text/plain", params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<Void>(error);
    }
    return Result<Void>();
}

} // namespace acl
} // namespace api
} // namespace ul
