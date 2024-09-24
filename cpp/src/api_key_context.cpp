// Copyright (c), CommunityLogiq Software

#include "ulsdk/api_key_context.h"

#include <curl/curl.h>

#include <algorithm>
#include <map>
#include <sstream>
#include <string>

#include "ulsdk/keys.h"
#include "ulsdk/ulsdk.h"

namespace ul {
static const char* REQUEST_TYPE = "ul1_request";
static const char* SIGNATURE_V1 = "UL1-ED25519";
static const char* HEADER_AUTHORIZATION = "authorization";
static const char* HEADER_X_UL_DATE = "x-ul-date";
static const char* HEADER_CONTENT_TYPE = "content-type";
static const char* SIGNED_HEADERS[] = {HEADER_X_UL_DATE};

class CurlSlistHandle {
    struct curl_slist* _slist;

public:
    CurlSlistHandle() : _slist(nullptr) {}

    ~CurlSlistHandle() {
        curl_slist_free_all(_slist);
    }

    CurlSlistHandle(const CurlSlistHandle&) = delete;

    struct curl_slist* get() {
        return _slist;
    }

    void set(struct curl_slist* slist) {
        _slist = slist;
    }
};

class CurlHandle {
    CURL* _curl;
    char* _error_buffer;

public:
    CurlHandle() {
        _error_buffer = new char[CURL_ERROR_SIZE];
        _curl = curl_easy_init();
        curl_easy_setopt(_curl, CURLOPT_ERRORBUFFER, _error_buffer);
    }

    ~CurlHandle() {
        curl_easy_cleanup(_curl);
        delete[] _error_buffer;
    }

    CurlHandle(const CurlHandle&) = delete;

    bool ok() const {
        return _curl != nullptr;
    }

    operator CURL*() const {
        return _curl;
    }

    const char* error_buffer() const {
        return _error_buffer;
    }
};

static Result<std::vector<uint8_t>>
raise_for_status(CURL* curl, std::vector<uint8_t> response) {
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (code >= 400) {
        return Result<std::vector<uint8_t>>(
            Error((int)code, std::string(response.begin(), response.end()))
        );
    }

    return Result<std::vector<uint8_t>>(response);
}

static std::string add_params(
    CURL* curl,
    const std::string& url,
    const std::vector<std::pair<std::string, std::string>>& params
) {
    std::string result = url;
    if (params.empty()) {
        return result;
    }

    result.push_back('?');
    for (const auto& pair : params) {
        if (result.back() != '?') {
            result.push_back('&');
        }
        result += pair.first;
        result.push_back('=');
        const char* encoded =
            curl_easy_escape(curl, pair.second.c_str(), pair.second.size());
        result += encoded;
        curl_free((void*)encoded);
    }

    return result;
}

static size_t
write_callback(void* ptr, size_t size, size_t nmemb, void* userdata) {
    std::vector<uint8_t>& response = *(std::vector<uint8_t>*)userdata;
    const size_t total = size * nmemb;
    response.insert(response.end(), (uint8_t*)ptr, (uint8_t*)ptr + total);
    return total;
}

static std::string to_upper(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

static std::string to_lower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

static std::string canonicalize_path(const std::string& path) {
    if (path.empty()) {
        return "/";
    }

    if (path[0] != '/') {
        return std::string("/") + path;
    }

    return path;
}

static Result<std::string> canonicalize_query_string(
    CURL* curl,
    const std::vector<std::pair<std::string, std::string>>& query
) {
    if (query.empty()) {
        return Result<std::string>(std::string());
    }

    std::vector<std::pair<std::string, std::string>> query_copy = query;
    std::sort(
        query_copy.begin(),
        query_copy.end(),
        [](const auto& a, const auto& b) { return a.first < b.first; }
    );

    std::string result;
    for (const auto& pair : query) {
        if (pair.first == "X-UL-Signature") {
            continue;
        }

        const char* encoded =
            curl_easy_escape(curl, pair.second.c_str(), pair.second.size());
        if (encoded == nullptr) {
            return Result<std::string>(Error("Failed to encode query parameter")
            );
        }
        const std::string value(encoded);
        curl_free((void*)encoded);

        if (!result.empty()) {
            result.push_back('&');
        }
        result += pair.first;
        result.push_back('=');
        result += value;
    }

    return Result<std::string>(result);
}

static Result<std::string> canonicalize_headers(
    const std::vector<std::string>& signed_headers,
    const std::vector<std::pair<std::string, std::string>>& headers
) {
    std::vector<std::string> sorted_signed_headers;
    for (const auto& header : signed_headers) {
        sorted_signed_headers.push_back(to_lower(header));
    }
    std::sort(sorted_signed_headers.begin(), sorted_signed_headers.end());

    std::string canonical_header_parts;
    for (const auto& header : sorted_signed_headers) {
        for (const auto& pair : headers) {
            if (to_lower(pair.first) == header) {
                if (!canonical_header_parts.empty()) {
                    canonical_header_parts.push_back('\n');
                }

                canonical_header_parts += header;
                canonical_header_parts.push_back(':');
                canonical_header_parts += pair.second;
            }
        }
    }

    return Result<std::string>(canonical_header_parts);
}

static std::string hash(size_t len, const uint8_t* data) {
    uint8_t hash_out[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash_out, data, len);

    return hex(crypto_hash_sha256_BYTES, hash_out);
}

static Result<std::pair<std::string, std::string>> canonicalize_request(
    const CurlHandle& curl,
    const std::string& method,
    const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& query,
    const std::vector<std::pair<std::string, std::string>>& headers,
    const std::vector<std::string>& signed_headers,
    const std::vector<uint8_t>& body
) {
    const std::string canonical_path = canonicalize_path(path);

    const Result<std::string> canonical_query_res =
        canonicalize_query_string(curl, query);
    if (std::holds_alternative<Error>(canonical_query_res)) {
        return Result<std::pair<std::string, std::string>>(
            std::get<Error>(canonical_query_res)
        );
    }
    const std::string canonical_query_string =
        std::get<std::string>(canonical_query_res);

    const Result<std::string> canonical_headers_res =
        canonicalize_headers(signed_headers, headers);
    if (std::holds_alternative<Error>(canonical_headers_res)) {
        return Result<std::pair<std::string, std::string>>(
            std::get<Error>(canonical_headers_res)
        );
    }
    const std::string canonical_headers =
        std::get<std::string>(canonical_headers_res);

    std::string signed_headers_str;
    for (const auto& header : signed_headers) {
        if (!signed_headers_str.empty()) {
            signed_headers_str.push_back(';');
        }
        signed_headers_str += header;
    }

    std::stringstream ss;
    ss << to_upper(method) << '\n'
       << canonical_path << '\n'
       << canonical_query_string << '\n'
       << canonical_headers << '\n'
       << signed_headers_str << '\n'
       << hash(body.size(), body.data());

    const std::string s = ss.str();
    const std::string h = hash(s.size(), (const uint8_t*)s.c_str());

    return Result<std::pair<std::string, std::string>>(
        std::make_pair(h, signed_headers_str)
    );
}

static Result<std::string> generate_auth_header(
    const CurlHandle& curl,
    const Key& key,
    const std::string& method,
    const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& query,
    std::vector<std::pair<std::string, std::string>>& headers,
    const std::vector<uint8_t>& body
) {
    const unsigned long ts = time(nullptr);

    headers.push_back(std::make_pair(HEADER_X_UL_DATE, std::to_string(ts)));

    std::vector<std::string> signed_headers;
    for (const auto& header : SIGNED_HEADERS) {
        signed_headers.push_back(header);
    }

    const Result<std::pair<std::string, std::string>> canonical_request_res =
        canonicalize_request(
            curl,
            method,
            path,
            query,
            headers,
            signed_headers,
            body
        );

    if (std::holds_alternative<Error>(canonical_request_res)) {
        return Result<std::string>(std::get<Error>(canonical_request_res));
    }

    const std::pair<std::string, std::string> canonical_request =
        std::get<std::pair<std::string, std::string>>(canonical_request_res);
    const std::string request_hash = canonical_request.first;
    const std::string signed_header_string = canonical_request.second;

    std::stringstream scope;
    scope << key.user_id_.to_string() << '/' << ts << '/'
          << to_string(key.region_) << '/' << REQUEST_TYPE;

    std::stringstream signing_string_stream;
    signing_string_stream << SIGNATURE_V1 << '\n'
                          << scope.str() << '\n'
                          << request_hash;
    const std::string signing_string = signing_string_stream.str();

    unsigned char signature[crypto_sign_BYTES];
    crypto_sign_detached(
        signature,
        nullptr,
        (const uint8_t*)signing_string.c_str(),
        signing_string.size(),
        key.secret_key_.data()
    );
    const std::string hex_signature = hex(crypto_sign_BYTES, signature);

    std::stringstream header;
    header << SIGNATURE_V1 << " Credential=" << key.access_key_ << '/'
           << scope.str() << ", SignedHeaders=" << signed_header_string
           << ", Signature=" << hex_signature;

    return Result<std::string>(header.str());
}

ApiKeyContext::ApiKeyContext(const Key& key, const Environment& environment) :
    environment_(environment),
    key_(key) {}

ApiKeyContext::~ApiKeyContext() {}

Region ApiKeyContext::region() const {
    return key_.region_;
}

Environment ApiKeyContext::environment() const {
    return environment_;
}

Result<std::vector<uint8_t>> ApiKeyContext::get(
    const std::string& path,
    const std::map<std::string, std::string>& params_map,
    const std::map<std::string, std::string>& headers_map
) const {
    const Result<std::string> endpoint =
        get_endpoint(key_.region_, environment_, path);
    if (std::holds_alternative<Error>(endpoint)) {
        return Result<std::vector<uint8_t>>(std::get<Error>(endpoint));
    }

    CurlHandle curl;
    if (!curl.ok()) {
        return Result<std::vector<uint8_t>>(Error("Failed to initialize curl"));
    }

    const auto params = std::vector<std::pair<std::string, std::string>>(
        params_map.begin(),
        params_map.end()
    );
    auto headers = std::vector<std::pair<std::string, std::string>>(
        headers_map.begin(),
        headers_map.end()
    );

    const Result<std::string> auth_header_res = generate_auth_header(
        curl,
        key_,
        "GET",
        path,
        params,
        headers,
        std::vector<uint8_t>()
    );
    if (std::holds_alternative<Error>(auth_header_res)) {
        return Result<std::vector<uint8_t>>(std::get<Error>(auth_header_res));
    }

    const std::string auth_header = std::get<std::string>(auth_header_res);

    CurlSlistHandle slist;
    for (const auto& pair : headers) {
        std::stringstream header_stream;
        header_stream << pair.first << ": " << pair.second;
        const std::string header = header_stream.str();

        slist.set(curl_slist_append(slist.get(), header.c_str()));
    }
    std::stringstream auth_header_stream;
    auth_header_stream << HEADER_AUTHORIZATION << ": " << auth_header;
    const std::string auth_header_str = auth_header_stream.str();
    slist.set(curl_slist_append(slist.get(), auth_header_str.c_str()));

    std::vector<uint8_t> response;
    const std::string url =
        add_params(curl, std::get<std::string>(endpoint), params);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist.get());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    if (curl_easy_perform(curl) != CURLE_OK) {
        return Result<std::vector<uint8_t>>(Error(curl.error_buffer()));
    }

    return raise_for_status(curl, response);
}

Result<std::vector<uint8_t>> ApiKeyContext::put(
    const std::string& path,
    const std::vector<uint8_t>& data,
    const std::string& mimetype,
    const std::map<std::string, std::string>& params_map,
    const std::map<std::string, std::string>& headers_map
) const {
    const Result<std::string> endpoint =
        get_endpoint(key_.region_, environment_, path);
    if (std::holds_alternative<Error>(endpoint)) {
        return Result<std::vector<uint8_t>>(std::get<Error>(endpoint));
    }

    CurlHandle curl;
    if (!curl.ok()) {
        return Result<std::vector<uint8_t>>(Error("Failed to initialize curl"));
    }

    const auto params = std::vector<std::pair<std::string, std::string>>(
        params_map.begin(),
        params_map.end()
    );
    auto headers = std::vector<std::pair<std::string, std::string>>(
        headers_map.begin(),
        headers_map.end()
    );

    const Result<std::string> auth_header_res =
        generate_auth_header(curl, key_, "PUT", path, params, headers, data);
    if (std::holds_alternative<Error>(auth_header_res)) {
        return Result<std::vector<uint8_t>>(std::get<Error>(auth_header_res));
    }

    const std::string auth_header = std::get<std::string>(auth_header_res);

    CurlSlistHandle slist;
    for (const auto& pair : headers) {
        std::stringstream header_stream;
        header_stream << pair.first << ": " << pair.second;
        const std::string header = header_stream.str();

        slist.set(curl_slist_append(slist.get(), header.c_str()));
    }

    std::stringstream auth_header_stream;
    auth_header_stream << HEADER_AUTHORIZATION << ": " << auth_header;
    const std::string auth_header_str = auth_header_stream.str();
    slist.set(curl_slist_append(slist.get(), auth_header_str.c_str()));

    std::stringstream content_type_stream;
    content_type_stream << HEADER_CONTENT_TYPE << ": " << mimetype;
    const std::string content_type = content_type_stream.str();
    slist.set(curl_slist_append(slist.get(), content_type.c_str()));

    std::vector<uint8_t> response;
    const std::string url =
        add_params(curl, std::get<std::string>(endpoint), params);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist.get());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.size());
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    if (curl_easy_perform(curl) != CURLE_OK) {
        return Result<std::vector<uint8_t>>(Error(curl.error_buffer()));
    }

    return raise_for_status(curl, response);
}

Result<std::vector<uint8_t>> ApiKeyContext::post(
    const std::string& path,
    const std::vector<uint8_t>& data,
    const std::string& mimetype,
    const std::map<std::string, std::string>& params_map,
    const std::map<std::string, std::string>& headers_map
) const {
    const Result<std::string> endpoint =
        get_endpoint(key_.region_, environment_, path);
    if (std::holds_alternative<Error>(endpoint)) {
        return Result<std::vector<uint8_t>>(std::get<Error>(endpoint));
    }

    CurlHandle curl;
    if (!curl.ok()) {
        return Result<std::vector<uint8_t>>(Error("Failed to initialize curl"));
    }

    const auto params = std::vector<std::pair<std::string, std::string>>(
        params_map.begin(),
        params_map.end()
    );
    auto headers = std::vector<std::pair<std::string, std::string>>(
        headers_map.begin(),
        headers_map.end()
    );

    const Result<std::string> auth_header_res =
        generate_auth_header(curl, key_, "POST", path, params, headers, data);
    if (std::holds_alternative<Error>(auth_header_res)) {
        return Result<std::vector<uint8_t>>(std::get<Error>(auth_header_res));
    }

    const std::string auth_header = std::get<std::string>(auth_header_res);

    CurlSlistHandle slist;
    for (const auto& pair : headers) {
        std::stringstream header_stream;
        header_stream << pair.first << ": " << pair.second;
        const std::string header = header_stream.str();

        slist.set(curl_slist_append(slist.get(), header.c_str()));
    }

    std::stringstream auth_header_stream;
    auth_header_stream << HEADER_AUTHORIZATION << ": " << auth_header;
    const std::string auth_header_str = auth_header_stream.str();
    slist.set(curl_slist_append(slist.get(), auth_header_str.c_str()));

    std::stringstream content_type_stream;
    content_type_stream << HEADER_CONTENT_TYPE << ": " << mimetype;
    const std::string content_type = content_type_stream.str();
    slist.set(curl_slist_append(slist.get(), content_type.c_str()));

    std::vector<uint8_t> response;
    const std::string url =
        add_params(curl, std::get<std::string>(endpoint), params);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist.get());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.size());
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    if (curl_easy_perform(curl) != CURLE_OK) {
        return Result<std::vector<uint8_t>>(Error(curl.error_buffer()));
    }

    return raise_for_status(curl, response);
}

Result<std::vector<uint8_t>> ApiKeyContext::upload(
    const std::string& path,
    const std::vector<File>& files
) const {
    // This implementation manually constructs the request body as the entire
    // body is needed in order to calculate the signature, which I don't think
    // we can do with libcurl's multipart form data support.
    const unsigned long ts = time(nullptr);
    std::stringstream boundary_stream;
    boundary_stream << "--UL1-multipart-" << ts;
    const std::string boundary = boundary_stream.str();
    const std::string crlf = "\r\n";

    std::vector<uint8_t> body;
    body.insert(body.end(), boundary.begin(), boundary.end());
    body.insert(body.end(), crlf.begin(), crlf.end());

    for (const auto& file : files) {
        if (!body.empty()) {
            body.insert(body.end(), boundary.begin(), boundary.end());
            body.insert(body.end(), crlf.begin(), crlf.end());
        }

        std::stringstream disposition_header;
        disposition_header << "Content-Disposition: form-data; name=\""
                           << file.name << "\"; filename=\"" << file.name
                           << "\"\r\n";
        disposition_header << "Content-Type:" << file.mimetype << "\r\n\r\n";
        const std::string header = disposition_header.str();

        body.insert(body.end(), header.begin(), header.end());
        body.insert(body.end(), file.data.begin(), file.data.end());
    }
    body.insert(body.end(), boundary.begin(), boundary.end());
    body.push_back((uint8_t)'-');
    body.push_back((uint8_t)'-');

    std::stringstream mime_type;
    mime_type << "multipart/form-data; boundary=\"" << boundary << "\"";

    return post(path, body, mime_type.str(), {}, {});
}

Result<std::vector<uint8_t>> ApiKeyContext::del(
    const std::string& path,
    const std::map<std::string, std::string>& params_map,
    const std::map<std::string, std::string>& headers_map
) const {
    const Result<std::string> endpoint =
        get_endpoint(key_.region_, environment_, path);
    if (std::holds_alternative<Error>(endpoint)) {
        return Result<std::vector<uint8_t>>(std::get<Error>(endpoint));
    }

    CurlHandle curl;
    if (!curl.ok()) {
        return Result<std::vector<uint8_t>>(Error("Failed to initialize curl"));
    }

    const auto params = std::vector<std::pair<std::string, std::string>>(
        params_map.begin(),
        params_map.end()
    );
    auto headers = std::vector<std::pair<std::string, std::string>>(
        headers_map.begin(),
        headers_map.end()
    );

    const Result<std::string> auth_header_res = generate_auth_header(
        curl,
        key_,
        "DELETE",
        path,
        params,
        headers,
        std::vector<uint8_t>()
    );
    if (std::holds_alternative<Error>(auth_header_res)) {
        return Result<std::vector<uint8_t>>(std::get<Error>(auth_header_res));
    }

    const std::string auth_header = std::get<std::string>(auth_header_res);

    CurlSlistHandle slist;
    for (const auto& pair : headers) {
        std::stringstream header_stream;
        header_stream << pair.first << ": " << pair.second;
        const std::string header = header_stream.str();

        slist.set(curl_slist_append(slist.get(), header.c_str()));
    }

    std::stringstream auth_header_stream;
    auth_header_stream << HEADER_AUTHORIZATION << ": " << auth_header;
    const std::string auth_header_str = auth_header_stream.str();
    slist.set(curl_slist_append(slist.get(), auth_header_str.c_str()));

    std::vector<uint8_t> response;
    const std::string url =
        add_params(curl, std::get<std::string>(endpoint), params);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist.get());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

    if (curl_easy_perform(curl) != CURLE_OK) {
        return Result<std::vector<uint8_t>>(Error(curl.error_buffer()));
    }

    return raise_for_status(curl, response);
}
}  // namespace ul
