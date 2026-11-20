// Copyright (c), CommunityLogiq Software

#include "ulsdk/request_context.h"

#include <cassert>
#include <sstream>
#include <string>

#include "ulsdk/ulsdk.h"

namespace ul {
Result<Void> RequestContext::get_stream(
    const std::string& path,
    const std::map<std::string, std::string>& params,
    const std::map<std::string, std::string>& headers,
    const BodySink& sink
) const {
    const Result<std::vector<uint8_t>> res = get(path, params, headers);
    if (std::holds_alternative<Error>(res)) {
        return Result<Void>(std::get<Error>(res));
    }

    const std::vector<uint8_t>& body = std::get<std::vector<uint8_t>>(res);
    if (!body.empty() && !sink(body.data(), body.size())) {
        return Result<Void>(Error("The sink stopped the request"));
    }

    return Result<Void>(Void());
}

Result<std::string>
get_endpoint(Region region, Environment environment, const std::string& api) {
    const char* region_str = nullptr;
    switch (region) {
        case Region::US:
            region_str = "us";
            break;
        case Region::CA:
            region_str = "ca";
            break;
        default:
            return Result<std::string>(Error("invalid region specified"));
    }
    assert(region_str != nullptr);

    const char* environment_str = nullptr;
    switch (environment) {
        case Environment::Prod:
            environment_str = "home";
            break;
        case Environment::Stage:
            environment_str = "stage";
            break;
        default:
            return Result<std::string>(Error("invalid environment specified"));
    }
    assert(environment_str != nullptr);

    std::stringstream ss;
    ss << "https://" << environment_str << ".urbanlogiq." << region_str << api;
    return Result<std::string>(ss.str());
}
}  // namespace ul
