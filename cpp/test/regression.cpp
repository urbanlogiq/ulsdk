// Copyright (c), CommunityLogiq Software

#include "test.h"
#include "ulsdk/api/datacatalog.h"
#include "ulsdk/api/drive.h"
#include "ulsdk/api_key_context.h"
#include "ulsdk/keys.h"

ul::Result<ul::Void>
regression_test_parameter_replacement(ul::RequestContext&) {
    MockContext ctx;

    const std::string idstr = "010013a8-0fdb-e894-4885-a50e003ddf6a";
    ul::Uuid id = ul::Uuid(idstr);
    ul::api::datacatalog::stream_put_json(ctx, id, {});

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
        ul::api::datacatalog::stream_put_json(ctx, id, data);

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

ul::Result<ul::Void> regression_test_range_headers(ul::RequestContext&) {
    MockContext ctx;
    const ul::types::ObjectId id("00000000-0000-0000-0000-000000000000");
    const ul::BodySink sink = [](const uint8_t*, size_t) { return true; };

    ul::api::drive::get_file_stream(ctx, id, "bytes=6-", "\"tag\"", sink);
    const std::map<std::string, std::string> expected = {
        {"Range", "bytes=6-"},
        {"If-Range", "\"tag\""},
    };
    if (ctx.headers_ != expected) {
        return ul::Error("The request does not have the range headers");
    }

    ul::api::drive::get_file_stream(ctx, id, std::nullopt, std::nullopt, sink);
    if (!ctx.headers_.empty()) {
        return ul::Error(
            "The request has headers that the caller did not give"
        );
    }

    return ul::Void();
}

ApiTest regression_test_range_headers_obj(
    regression_test_range_headers,
    "regression::test_range_headers",
    &regression_test_root
);

ul::Result<ul::Void> regression_test_header_line_break(ul::RequestContext&) {
    // The key is not valid. The context must fail before it makes a request.
    const ul::Key key(
        ul::Uuid("00000000-0000-0000-0000-000000000000"),
        ul::Region::CA,
        "test-access-key",
        std::vector<uint8_t>(crypto_sign_SECRETKEYBYTES)
    );
    ul::ApiKeyContext ctx(key, ul::Environment::Stage);
    const ul::types::ObjectId id("00000000-0000-0000-0000-000000000000");
    const ul::BodySink sink = [](const uint8_t*, size_t) { return true; };

    const auto result = ul::api::drive::get_file_stream(
        ctx,
        id,
        "bytes=0-\r\nx-other: 1",
        std::nullopt,
        sink
    );

    if (!std::holds_alternative<ul::Error>(result)) {
        return ul::Error("The context sent a header value with a line break");
    }
    const ul::Error error = std::get<ul::Error>(result);
    if (error.message_ != "Invalid value for header Range") {
        return ul::Error("Unexpected error: " + error.message_);
    }

    return ul::Void();
}

ApiTest regression_test_header_line_break_obj(
    regression_test_header_line_break,
    "regression::test_header_line_break",
    &regression_test_root
);
