// Copyright (c), CommunityLogiq Software

#pragma once

#include "ulsdk/ulsdk.h"

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


