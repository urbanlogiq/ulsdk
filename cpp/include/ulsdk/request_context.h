// Copyright (c), CommunityLogiq Software

#pragma once

#include <map>
#include <string>
#include <variant>
#include <vector>

#include "ulsdk/ulsdk.h"

namespace ul {
struct File {
    std::string name;
    std::string mimetype;
    std::vector<uint8_t> data;
};

Result<std::string>
get_endpoint(Region region, Environment environment, const std::string& api);

struct RequestContext {
    virtual ~RequestContext() = default;

    virtual Region region() const = 0;
    virtual Environment environment() const = 0;

    virtual Result<std::vector<uint8_t>>
    get(const std::string& path,
        const std::map<std::string, std::string>& params,
        const std::map<std::string, std::string>& headers) const = 0;

    virtual Result<std::vector<uint8_t>>
    put(const std::string& path,
        const std::vector<uint8_t>& data,
        const std::string& mimetype,
        const std::map<std::string, std::string>& params,
        const std::map<std::string, std::string>& headers) const = 0;

    virtual Result<std::vector<uint8_t>> post(
        const std::string& path,
        const std::vector<uint8_t>& data,
        const std::string& mimetype,
        const std::map<std::string, std::string>& params,
        const std::map<std::string, std::string>& headers
    ) const = 0;

    virtual Result<std::vector<uint8_t>>
    upload(const std::string& path, const std::vector<File>& files) const = 0;

    virtual Result<std::vector<uint8_t>>
    del(const std::string& path,
        const std::map<std::string, std::string>& params,
        const std::map<std::string, std::string>& headers) const = 0;
};
}  // namespace ul
