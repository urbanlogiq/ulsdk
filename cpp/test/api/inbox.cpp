// Copyright (c), CommunityLogiq Software
// 
// THIS FILE IS AUTOGENERATED, DO NOT EDIT

#include "ulsdk/api/inbox.h"

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

#include "test.h"

namespace inbox {

ul::Result<ul::Void>
test_fetch(ul::RequestContext &ctx) {
    ::ul::api::inbox::fetch(
        ctx,
        std::string()
    );
    return ul::Void();
}

ApiTest test_fetch_obj(test_fetch, "inbox::fetch", &link_only_api_test_root);

ul::Result<ul::Void>
test_clear_all_status(ul::RequestContext &ctx) {
    ::ul::api::inbox::clear_all_status(
        ctx,
        std::string()
    );
    return ul::Void();
}

ApiTest test_clear_all_status_obj(test_clear_all_status, "inbox::clear_all_status", &link_only_api_test_root);

ul::Result<ul::Void>
test_set_status(ul::RequestContext &ctx) {
    ::ul::api::inbox::set_status(
        ctx,
        std::string(),
        ul::Uuid("00000000-0000-0000-0000-000000000000"),
        0
    );
    return ul::Void();
}

ApiTest test_set_status_obj(test_set_status, "inbox::set_status", &link_only_api_test_root);

ul::Result<ul::Void>
test_clear_status(ul::RequestContext &ctx) {
    ::ul::api::inbox::clear_status(
        ctx,
        std::string(),
        ul::Uuid("00000000-0000-0000-0000-000000000000")
    );
    return ul::Void();
}

ApiTest test_clear_status_obj(test_clear_status, "inbox::clear_status", &link_only_api_test_root);

} // namespace inbox