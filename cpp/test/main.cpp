// Copyright (c), CommunityLogiq Software

#include <cstdlib>
#include <iostream>
#include <variant>

#include "test.h"
#include "ulsdk/api_key_context.h"
#include "ulsdk/keys.h"
#include "ulsdk/ulsdk.h"

ApiTest* idempotent_api_test_root;
ApiTest* mutating_api_test_root;
ApiTest* link_only_api_test_root;
ApiTest* regression_test_root;
TypeTest* type_test_root;

struct TestConfig {
    const std::string user_;
    ul::Region region_;
    const std::string access_key_;
    const std::string secret_key_;

    TestConfig(
        const std::string& user,
        ul::Region region,
        const std::string& access_key,
        const std::string& secret_key
    ) :
        user_(user),
        region_(region),
        access_key_(access_key),
        secret_key_(secret_key) {}
};

bool filter_test(const std::vector<std::string>& filters, const char* test) {
    if (filters.empty()) {
        return true;
    }

    for (auto& filter : filters) {
        if (std::strstr(test, filter.c_str()) != NULL) {
            return true;
        }
    }

    return false;
}

std::string string_from_cstr(char* s) {
    if (s == nullptr) {
        return std::string();
    }

    return std::string(s);
}

void run_api_tests(
    ul::ApiKeyContext& ctx,
    ApiTest* p,
    const std::vector<std::string>& filters,
    int& failed
) {
    while (p != nullptr) {
        if (filter_test(filters, p->name)) {
            std::cout << "  Running test " << p->name << " ... ";
            const auto result = p->fn(ctx);
            if (std::holds_alternative<ul::Error>(result)) {
                const ul::Error error = std::get<ul::Error>(result);
                std::cout << "FAILED (";
                if (error.code_ != 0) {
                    std::cout << "code: " << error.code_ << " ";
                }
                std::cout << "message: " << error.message_ << ")" << std::endl;
                ++failed;
            } else {
                std::cout << "ok" << std::endl;
            }
        }

        p = p->next;
    }
}

int main(int argc, char** argv) {
    const std::string ca_user = string_from_cstr(std::getenv("CA_USER"));
    const std::string ca_access_key =
        string_from_cstr(std::getenv("CA_ACCESS_KEY"));
    const std::string ca_secret_key =
        string_from_cstr(std::getenv("CA_SECRET_KEY"));
    const std::string us_user = string_from_cstr(std::getenv("US_USER"));
    const std::string us_access_key =
        string_from_cstr(std::getenv("US_ACCESS_KEY"));
    const std::string us_secret_key =
        string_from_cstr(std::getenv("US_SECRET_KEY"));
    const std::string run_mutating_tests =
        string_from_cstr(std::getenv("RUN_MUTATING_TESTS"));

    const TestConfig test_configs[] = {
        TestConfig(ca_user, ul::Region::CA, ca_access_key, ca_secret_key),
        TestConfig(us_user, ul::Region::US, us_access_key, us_secret_key),
    };

    int failed = 0;

    std::vector<std::string> filters;
    for (int i = 1; i < argc; ++i) {
        filters.push_back(argv[i]);
    }

    for (const TestConfig& config : test_configs) {
        if (config.user_.empty() || config.access_key_.empty()
            || config.secret_key_.empty()) {
            std::cerr << "Missing access key or secret key for "
                      << (config.region_ == ul::Region::CA ? "CA" : "US")
                      << std::endl;
            continue;
        }

        ul::Key key = ul::Key(
            config.user_,
            config.region_,
            config.access_key_,
            config.secret_key_
        );
        ul::Environment env = ul::Environment::Prod;
        ul::ApiKeyContext ctx(key, env);

        std::cout << "Running tests for "
                  << (config.region_ == ul::Region::CA ? "CA" : "US")
                  << std::endl;

        run_api_tests(ctx, idempotent_api_test_root, filters, failed);
        run_api_tests(ctx, regression_test_root, filters, failed);

        if (run_mutating_tests.empty()) {
            run_api_tests(ctx, mutating_api_test_root, filters, failed);
        }
    }

    ApiTest* p = link_only_api_test_root;
    std::cout << "Listing link-only tests" << std::endl;
    while (p != nullptr) {
        if (filter_test(filters, p->name)) {
            std::cout << "  Running test " << p->name << " ... ok" << std::endl;
        }

        p = p->next;
    }

    std::cout << "Running type tests" << std::endl;
    TypeTest* t = type_test_root;
    while (t != nullptr) {
        if (filter_test(filters, t->name)) {
            std::cout << "  Running test " << t->name << " ... ";
            if (!t->fn()) {
                std::cout << "FAILED" << std::endl;
                ++failed;
            }
            std::cout << "ok" << std::endl;
        }

        t = t->next;
    }

    if (failed != 0) {
        std::cout << failed << " TESTS FAILED" << std::endl;
        return 1;
    }

    std::cout << "all passed!" << std::endl;
    return 0;
}
