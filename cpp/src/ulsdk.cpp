// Copyright (c), CommunityLogiq Software

#include "ulsdk/ulsdk.h"

#include <sodium.h>

#ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunused-parameter"
#endif

#include <arrow/buffer.h>
#include <arrow/io/interfaces.h>
#include <arrow/ipc/reader.h>
#include <arrow/ipc/writer.h>
#include <arrow/record_batch.h>

#ifdef __GNUC__
    #pragma GCC diagnostic pop
#endif
#ifdef __clang__
    #pragma clang diagnostic pop
#endif

#include <cassert>
#include <memory>
#include <stdexcept>

namespace ul {
static uint8_t unhex(char c) {
    uint8_t value = 0;

    if (c >= '0' && c <= '9') {
        value = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        value = (c - 'a') + 10;
    } else if (c >= 'A' && c <= 'F') {
        value = (c - 'A') + 10;
    } else {
        throw std::invalid_argument("invalid hex character");
    }

    assert(value < 16);
    return value;
}

Uuid::Uuid(const uint8_t* b) {
    std::copy(b, b + UUID_BYTES, _bytes);
}

Uuid::Uuid(const std::string& str) {
    const size_t size = str.size();
    size_t i = 0;

    if (size == 36) {
        for (size_t ii = 0; ii < size;) {
            if (ii == 8 || ii == 13 || ii == 18 || ii == 23) {
                ++ii;
            } else {
                uint8_t hi = unhex(str[ii]) << 4;
                uint8_t lo = unhex(str[ii + 1]);
                uint8_t byte = hi | lo;

                _bytes[i++] = byte;
                ii += 2;
            }
        }
    } else if (size == 32) {
        for (size_t ii = 0; ii < size; ii += 2) {
            _bytes[i++] = unhex(str[ii]) << 4 | unhex(str[ii + 1]);
        }
    } else {
        throw std::invalid_argument("invalid UUID string");
    }
}

std::string Uuid::to_string() const {
    std::string result;
    result.reserve(36);

    result += hex(4, &_bytes[0]);
    result += '-';
    result += hex(2, &_bytes[4]);
    result += '-';
    result += hex(2, &_bytes[6]);
    result += '-';
    result += hex(2, &_bytes[8]);
    result += '-';
    result += hex(6, &_bytes[10]);

    return result;
}

std::string url_encode(const std::string& input) {
    CURL* curl = curl_easy_init();
    char* output = curl_easy_escape(curl, input.c_str(), input.size());
    std::string result = std::string(output);
    curl_free(output);
    curl_easy_cleanup(curl);

    return result;
}

int init() {
    if (sodium_init() == -1) {
        return -1;
    }

    return 0;
}

std::string hex(size_t len, const uint8_t* bytes) {
    std::string result;
    result.reserve(len * 2);

    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        const uint8_t b = bytes[i];
        const uint8_t hi = b >> 4;
        const uint8_t lo = b & 0x0f;
        result.push_back(hex_chars[hi]);
        result.push_back(hex_chars[lo]);
    }

    return result;
}

std::string to_string(const Region& r) {
    switch (r) {
        case Region::CA:
            return "ca";
        case Region::US:
            return "us";
    }

    throw std::invalid_argument("invalid region");
}

struct VectorOutputStream: public arrow::io::OutputStream {
    bool closed_;
    std::vector<uint8_t> data_;

    VectorOutputStream() : closed_(false), data_() {}

    arrow::Result<int64_t> Tell() const override {
        return data_.size();
    }

    arrow::Status Write(const void* data, int64_t nbytes) override {
        const uint8_t* base = static_cast<const uint8_t*>(data);
        data_.insert(data_.end(), base, base + nbytes);
        return arrow::Status::OK();
    }

    arrow::Status Write(const std::shared_ptr<arrow::Buffer>& data) override {
        const uint8_t* base = data->data();
        const int64_t size = data->size();
        data_.insert(data_.end(), base, base + size);
        return arrow::Status::OK();
    }

    arrow::Status Flush() override {
        return arrow::Status::OK();
    }

    arrow::Status Close() override {
        closed_ = true;
        return arrow::Status::OK();
    }

    bool closed() const override {
        return closed_;
    }

    std::vector<uint8_t> take() {
        return std::move(data_);
    }
};

struct VectorInputStream: public arrow::io::InputStream {
    const std::vector<uint8_t>& data_;
    size_t pos_;
    bool closed_;

    VectorInputStream(const std::vector<uint8_t>& data) :
        data_(data),
        pos_(0),
        closed_(false) {}

    bool supports_zero_copy() const override {
        return true;
    }

    arrow::Result<int64_t> Read(int64_t nbytes, void* out) override {
        const uint8_t* base = data_.data() + pos_;
        pos_ += nbytes;
        std::memcpy(out, base, nbytes);

        return nbytes;
    }

    arrow::Result<std::shared_ptr<arrow::Buffer>> Read(int64_t nbytes
    ) override {
        const uint8_t* base = data_.data() + pos_;
        pos_ += nbytes;
        return std::make_shared<arrow::Buffer>(base, nbytes);
    }

    arrow::Status Close() override {
        closed_ = true;
        return arrow::Status::OK();
    }

    arrow::Result<int64_t> Tell() const override {
        return pos_;
    }

    bool closed() const override {
        return closed_;
    }
};

static arrow::Result<std::vector<std::shared_ptr<arrow::RecordBatch>>>
to_arrow_impl(const std::vector<uint8_t>& input) {
    const std::shared_ptr<arrow::io::InputStream> stream =
        std::make_shared<VectorInputStream>(input);

    std::vector<std::shared_ptr<arrow::RecordBatch>> result;

    {
        ARROW_ASSIGN_OR_RAISE(
            auto reader,
            arrow::ipc::RecordBatchStreamReader::Open(stream)
        );

        while (true) {
            std::shared_ptr<arrow::RecordBatch> batch;
            ARROW_RETURN_NOT_OK(reader->ReadNext(&batch));

            if (!batch) {
                break;
            }

            if (batch->num_rows() != 0) {
                result.push_back(batch);
            }
        }

        ARROW_RETURN_NOT_OK(reader->Close());
    }

    return result;
}

std::vector<std::shared_ptr<arrow::RecordBatch>>
to_arrow(const std::vector<uint8_t>& input) {
    auto result = to_arrow_impl(input);
    if (!result.ok()) {
        throw std::runtime_error(result.status().message());
    }

    return result.ValueOrDie();
}

static arrow::Result<std::vector<uint8_t>>
to_bytes_impl(const std::vector<std::shared_ptr<arrow::RecordBatch>>& input) {
    std::shared_ptr<VectorOutputStream> stream =
        std::make_shared<VectorOutputStream>();

    {
        ARROW_ASSIGN_OR_RAISE(
            auto writer,
            arrow::ipc::MakeStreamWriter(stream, input[0]->schema())
        );

        for (const auto& batch : input) {
            ARROW_RETURN_NOT_OK(writer->WriteRecordBatch(*batch));
        }

        ARROW_RETURN_NOT_OK(writer->Close());
    }

    return stream->take();
}

std::vector<uint8_t>
to_bytes(const std::vector<std::shared_ptr<arrow::RecordBatch>>& input) {
    if (input.empty()) {
        return std::vector<uint8_t>();
    }

    auto result = to_bytes_impl(input);
    if (!result.ok()) {
        throw std::runtime_error(result.status().message());
    }

    return result.ValueOrDie();
}

}  // namespace ul
