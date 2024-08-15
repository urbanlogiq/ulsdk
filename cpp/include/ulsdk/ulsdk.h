// Copyright (c), CommunityLogiq Software

#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>
#include <memory>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif

#include <arrow/result.h>

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#ifdef __clang__
#pragma clang diagnostic pop
#endif

namespace arrow {
class RecordBatch;
}

namespace ul {
const size_t UUID_BYTES = 16;

class Uuid {
    unsigned char _bytes[UUID_BYTES];

public:
    Uuid() = delete;
    Uuid(const Uuid& other) = default;
    Uuid(const unsigned char* bytes);
    Uuid(const std::string& str);

    std::string to_string() const;
};

enum class Region { CA, US };

enum class Environment {
    Prod,
    Stage,
};

struct Error {
    int code_;
    std::string message_;

    Error(int code, const std::string& message) :
        code_(code),
        message_(message) {}

    Error(const std::string& message) : code_(0), message_(message) {}
};

template<typename T>
struct AutoRelease {
    T* ptr;

    const T& operator*() const {
        return *ptr;
    }

    T& operator*() {
        return *ptr;
    }

    T* operator->() {
        return ptr;
    }

    const T* operator->() const {
        return ptr;
    }

    T* get() {
        return ptr;
    }

    const T* get() const {
        return ptr;
    }

    ~AutoRelease() {
        std::free((void*)ptr);
    }

    AutoRelease(T* p) : ptr(p) {}

    bool operator==(std::nullptr_t) const {
        return ptr == nullptr;
    }

    bool operator==(std::nullptr_t) {
        return ptr == nullptr;
    }
};

template<typename R>
using Result = std::variant<R, Error>;

struct Void {};

int init();
std::string hex(size_t len, const uint8_t* bytes);
std::string to_string(const Region& r);

typedef std::variant<int64_t, double, std::string, bool> JsonValue;

std::vector<std::shared_ptr<arrow::RecordBatch>>
to_arrow(const std::vector<uint8_t>& input);

std::vector<uint8_t>
to_bytes(const std::vector<std::shared_ptr<arrow::RecordBatch>>& input);

}  // namespace ul
