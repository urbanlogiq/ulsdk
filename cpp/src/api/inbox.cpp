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
#include "ulsdk/api/inbox.h"

namespace ul {
namespace api {
namespace inbox {

Result<::ul::types::Inbox>
fetch(
    ul::RequestContext &ctx,
    const std::string &folder
) {
    std::string path = "/v1/api/ulv2/inbox/:folder";
    const size_t folder_idx = path.find(":folder");
    path.replace(folder_idx, 2, folder);

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const Result<std::vector<uint8_t>> res = ctx.get(path, params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<::ul::types::Inbox>(error);
    }
    return ::ul::types::Inbox(std::get<std::vector<uint8_t>>(res));
}

Result<Void>
clear_all_status(
    ul::RequestContext &ctx,
    const std::string &folder
) {
    std::string path = "/v1/api/ulv2/inbox/:folder";
    const size_t folder_idx = path.find(":folder");
    path.replace(folder_idx, 2, folder);

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const auto res = ctx.get(path, params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<Void>(error);
    }
    return Result<Void>();
}

Result<Void>
set_status(
    ul::RequestContext &ctx,
    const std::string &folder,
    const Uuid &id,
    int64_t status
) {
    std::string path = "/v1/api/ulv2/inbox/:folder/:id/status/:status";
    const size_t folder_idx = path.find(":folder");
    path.replace(folder_idx, 2, folder);
    const size_t id_idx = path.find(":id");
    path.replace(id_idx, 2, id.to_string());
    const size_t status_idx = path.find(":status");
    path.replace(status_idx, 2, std::to_string(status));

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
clear_status(
    ul::RequestContext &ctx,
    const std::string &folder,
    const Uuid &id
) {
    std::string path = "/v1/api/ulv2/inbox/:folder/:id";
    const size_t folder_idx = path.find(":folder");
    path.replace(folder_idx, 2, folder);
    const size_t id_idx = path.find(":id");
    path.replace(id_idx, 2, id.to_string());

    std::map<std::string, std::string> params;

    std::map<std::string, std::string> headers;
    const auto res = ctx.get(path, params, headers);
    if (std::holds_alternative<Error>(res)) {
        const auto error = std::get<Error>(res);
        return Result<Void>(error);
    }
    return Result<Void>();
}

} // namespace inbox
} // namespace api
} // namespace ul