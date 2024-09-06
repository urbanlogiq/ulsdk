// Copyright (c), CommunityLogiq Software

#pragma once

#include "ulsdk/ulsdk.h"
#include "ulsdk/request_context.h"

namespace ul {
class RequestContext;
}

typedef ul::Result<ul::Void> (*ApiTestFn)(ul::RequestContext &context);
typedef bool (*TypeTestFn)(void);

struct ApiTest;
struct TypeTest;

extern ApiTest *idempotent_api_test_root;
extern ApiTest *mutating_api_test_root;
extern ApiTest *link_only_api_test_root;
extern ApiTest *regression_test_root;
extern TypeTest *type_test_root;

struct ApiTest {
    ApiTestFn fn;
    const char *name;
    ApiTest *next;

    ApiTest(ApiTestFn f, const char *n, ApiTest **root) : fn(f), name(n) {
        next = *root;
        *root = this;
    }
};

struct TypeTest {
    TypeTestFn fn;
    const char *name;
    TypeTest *next;

    TypeTest(TypeTestFn f, const char *n) : fn(f), name(n) {
        next = type_test_root;
        type_test_root = this;
    }
};

struct MockContext : public ul::RequestContext {
    std::string method_;
    std::string path_;
    std::string mimetype_;
    std::vector<uint8_t> data_;
    std::map<std::string, std::string> params_;
    std::map<std::string, std::string> headers_;

    void clear() const {
        MockContext *self = const_cast<MockContext *>(this);

        self->method_.clear();
        self->path_.clear();
        self->mimetype_.clear();
        self->data_.clear();
        self->params_.clear();
        self->headers_.clear();
    }

    ul::Region region() const override {
        return ul::Region::CA;
    }

    ul::Environment environment() const override {
        return ul::Environment::Prod;
    }

    ul::Result<std::vector<uint8_t>>
    get(const std::string& path,
        const std::map<std::string, std::string>& params,
        const std::map<std::string, std::string>& headers) const override {
        clear();

        MockContext *self = const_cast<MockContext *>(this);

        self->method_ = "GET";
        self->path_ = path;
        self->params_ = params;
        self->headers_ = headers;

        return std::vector<uint8_t>();
    }

    ul::Result<std::vector<uint8_t>>
    put(const std::string& path,
        const std::vector<uint8_t>& data,
        const std::string& mimetype,
        const std::map<std::string, std::string>& params,
        const std::map<std::string, std::string>& headers) const override {
        clear();

        MockContext *self = const_cast<MockContext *>(this);

        self->method_ = "PUT";
        self->path_ = path;
        self->data_ = data;
        self->mimetype_ = mimetype;
        self->params_ = params;
        self->headers_ = headers;

        return std::vector<uint8_t>();
    }

    ul::Result<std::vector<uint8_t>> post(
        const std::string& path,
        const std::vector<uint8_t>& data,
        const std::string& mimetype,
        const std::map<std::string, std::string>& params,
        const std::map<std::string, std::string>& headers
    ) const override {
        clear();

        MockContext *self = const_cast<MockContext *>(this);

        self->method_ = "POST";
        self->path_ = path;
        self->data_ = data;
        self->mimetype_ = mimetype;
        self->params_ = params;
        self->headers_ = headers;

        return std::vector<uint8_t>();
    }

    ul::Result<std::vector<uint8_t>>
    upload(const std::string& path, const std::vector<ul::File>& files) const override {
        clear();

        return std::vector<uint8_t>();
    }

    ul::Result<std::vector<uint8_t>>
    del(const std::string& path,
        const std::map<std::string, std::string>& params,
        const std::map<std::string, std::string>& headers) const override {
        clear();

        MockContext *self = const_cast<MockContext *>(this);

        self->method_ = "DELETE";
        self->path_ = path;
        self->params_ = params;
        self->headers_ = headers;

        return std::vector<uint8_t>();
    }
};
