// Copyright (c), CommunityLogiq Software

#pragma once

#include <curl/curl.h>

#include "ulsdk/keys.h"
#include "ulsdk/request_context.h"

namespace ul {
class ApiKeyContext: public RequestContext {
    Environment environment_;
    Key key_;

public:
    ApiKeyContext() = delete;

    ApiKeyContext(const Key& key, const Environment& environment);
    ~ApiKeyContext();

    Region region() const override;
    Environment environment() const override;

    Result<std::vector<uint8_t>>
    get(const std::string& path,
        const std::map<std::string, std::string>& params,
        const std::map<std::string, std::string>& headers) const override;

    Result<std::vector<uint8_t>>
    put(const std::string& path,
        const std::vector<uint8_t>& data,
        const std::string& mimetype,
        const std::map<std::string, std::string>& params,
        const std::map<std::string, std::string>& headers) const override;

    Result<std::vector<uint8_t>> post(
        const std::string& path,
        const std::vector<uint8_t>& data,
        const std::string& mimetype,
        const std::map<std::string, std::string>& params,
        const std::map<std::string, std::string>& headers
    ) const override;

    Result<std::vector<uint8_t>> upload(
        const std::string& path,
        const std::vector<File>& files
    ) const override;

    Result<Void>
    del(const std::string& path,
        const std::map<std::string, std::string>& params,
        const std::map<std::string, std::string>& headers) const override;
};
}  // namespace ul
