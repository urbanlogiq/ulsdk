// Copyright (c), CommunityLogiq Software

#include "test.h"
#include "ulsdk/api/datacatalog.h"

ul::Result<ul::Void>
regression_test_parameter_replacement(ul::RequestContext&) {
    MockContext ctx;

    const std::string idstr = "010013a8-0fdb-e894-4885-a50e003ddf6a";
    ul::Uuid id = ul::Uuid(idstr);
    ul::api::datacatalog::stream_put_json(ctx, id, std::nullopt, {});

    const std::string& path = ctx.path_;
    if (std::equal(idstr.rbegin(), idstr.rend(), path.rbegin())) {
        return ul::Void();
    }

    return ul::Error("Path does not end with ID");
}

ApiTest regression_test_parameter_replacement_obj(
    regression_test_parameter_replacement,
    "regression::test_parameter_replacement",
    &regression_test_root
);

ul::Result<ul::Void> derq_ingestion_test(ul::RequestContext& ctx) {
    if (ctx.region() != ul::Region::US) {
        return ul::Void();
    }

    const std::vector<std::map<std::string, ul::JsonValue>> data = {
        {
            {"intersection_id", "64c2a08b465ea95f46945ac5"},
            {"event_type", "STPV"},
            {"event_id", "0_50_1725593354601000_0"},
            {"timestamp", 1725593354601},
            {"detection_area", "North Leg"},
            {"camera_id", 0},
            {"class_1", "car"},
        }
    };

    const std::string idstr = "01009d67-af1f-da68-4f59-bcafb5910204";
    ul::Uuid id = ul::Uuid(idstr);
    const auto result =
        ul::api::datacatalog::stream_put_json(ctx, id, std::nullopt, data);

    if (std::holds_alternative<ul::Error>(result)) {
        const ul::Error error = std::get<ul::Error>(result);
        return ul::Result<ul::Void>(error);
    }

    return ul::Result<ul::Void>(ul::Void());
}

ApiTest derq_ingestion_test_obj(
    derq_ingestion_test,
    "regression::derq_ingestion_test",
    &regression_test_root
);
