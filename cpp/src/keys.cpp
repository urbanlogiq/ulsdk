// Copyright (c), CommunityLogiq Software

#include "ulsdk/keys.h"

namespace ul {

static std::vector<uint8_t> decode_b64(const std::string& b64) {
    const std::string index =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint8_t lookup_table[128] = {};
    for (size_t i = 0; i < index.length(); ++i) {
        lookup_table[(uint8_t)index[i]] = i;
    }

    const size_t length = b64.length();
    const size_t padding = b64[length - 2] == '=' ? 2
        : b64[length - 1] == '='                  ? 1
                                                  : 0;
    const size_t non_padded_length = (length - padding) & ~3;
    const size_t decoded_length = (3 * non_padded_length) / 4 + (3 - padding);

    std::vector<uint8_t> bytes;
    bytes.reserve(decoded_length);

    size_t i = 0;

    for (; i < non_padded_length; i += 4) {
        const uint32_t quad = (uint32_t(lookup_table[uint8_t(b64[i])]) << 18)
            | (uint32_t(lookup_table[uint8_t(b64[i + 1])]) << 12)
            | (uint32_t(lookup_table[uint8_t(b64[i + 2])]) << 6)
            | (uint32_t(lookup_table[uint8_t(b64[i + 3])]) << 0);
        bytes.push_back((quad >> 16) & 0xff);
        bytes.push_back((quad >> 8) & 0xff);
        bytes.push_back(quad & 0xff);
    }

    switch (padding) {
        case 2: {
            const uint32_t quad = (uint32_t(lookup_table[uint8_t(b64[i])]) << 2)
                | (uint32_t(lookup_table[uint8_t(b64[i + 1])]) >> 4);
            bytes.push_back(quad & 0xff);
            break;
        }
        case 1: {
            const uint32_t quad =
                (uint32_t(lookup_table[uint8_t(b64[i])]) << 10)
                | (uint32_t(lookup_table[uint8_t(b64[i + 1])]) << 4)
                | (uint32_t(lookup_table[uint8_t(b64[i + 2])]) >> 2);
            bytes.push_back((quad >> 8) & 0xff);
            bytes.push_back(quad & 0xff);
            break;
        }
        case 0:
        default:
            break;
    }

    return bytes;
}

static std::vector<uint8_t> decode_b64_secret_key(const std::string& secret_key
) {
    std::string b64 = secret_key;
    while (b64.length() % 4) {
        b64.push_back('"');
    }

    return decode_b64(b64);
}

Key::Key(
    const std::string& user_id,
    Region region,
    const std::string& access_key,
    const std::string& secret_key
) :
    user_id_(user_id),
    region_(region),
    access_key_(access_key),
    secret_key_(decode_b64_secret_key(secret_key)) {}

Key::Key(
    const Uuid& user_id,
    Region region,
    const std::string& access_key,
    const std::vector<uint8_t>& secret_key
) :
    user_id_(user_id),
    region_(region),
    access_key_(access_key),
    secret_key_(secret_key) {}

}  // namespace ul
