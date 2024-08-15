// Copyright (c), CommunityLogiq Software

#include <cassert>
#include <sstream>
#include <string>

#include "ulsdk/ulsdk.h"

namespace ul {
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
