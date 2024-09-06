// Copyright (c), CommunityLogiq Software

#include "test.h"

#include "ulsdk/api/datacatalog.h"

ul::Result<ul::Void>
regression_test_parameter_replacement(ul::RequestContext &) {
    MockContext ctx;

    const std::string idstr = "010013a8-0fdb-e894-4885-a50e003ddf6a";
    ul::Uuid id = ul::Uuid(idstr);
    ul::api::datacatalog::stream_put_json(ctx, id, std::nullopt, {});

    const std::string &path = ctx.path_;
    if (std::equal(idstr.rbegin(), idstr.rend(), path.rbegin())) {
        return ul::Void();
    }

    return ul::Error("Path does not end with ID");
}

ApiTest regression_test_parameter_replacement_obj(regression_test_parameter_replacement, "regression::test_parameter_replacement", &regression_test_root);
