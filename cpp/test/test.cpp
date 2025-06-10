// Copyright (c), CommunityLogiq Software

#include "test.h"

#include <arrow/api.h>
#include <arrow/io/api.h>
#include <arrow/ipc/api.h>

TestContext::TestContext(ul::RequestContext& context) :
    context_(context),
    response_() {}

TestContext::~TestContext() {}

ul::Region TestContext::region() const {
    return context_.region();
}

ul::Environment TestContext::environment() const {
    return context_.environment();
}

void TestContext::set_response(std::vector<uint8_t> response) {
    response_ = response;
}

ul::Result<std::vector<uint8_t>> TestContext::get(
    const std::string& path,
    const std::map<std::string, std::string>& params,
    const std::map<std::string, std::string>& headers
) const {
    const std::string echo_path = "/v1/echo/";
    const ul::Result<std::vector<uint8_t>> res =
        context_.get(echo_path, params, headers);

    if (std::holds_alternative<ul::Error>(res)) {
        return res;
    }

    return ul::Result<std::vector<uint8_t>>(response_);
}

ul::Result<std::vector<uint8_t>> TestContext::put(
    const std::string& path,
    const std::vector<uint8_t>& data,
    const std::string& mimetype,
    const std::map<std::string, std::string>& params,
    const std::map<std::string, std::string>& headers
) const {
    const std::string echo_path = "/v1/echo/";
    const ul::Result<std::vector<uint8_t>> res =
        context_.put(echo_path, data, mimetype, params, headers);

    if (std::holds_alternative<ul::Error>(res)) {
        return res;
    }

    return ul::Result<std::vector<uint8_t>>(response_);
}

ul::Result<std::vector<uint8_t>> TestContext::post(
    const std::string& path,
    const std::vector<uint8_t>& data,
    const std::string& mimetype,
    const std::map<std::string, std::string>& params,
    const std::map<std::string, std::string>& headers
) const {
    const std::string echo_path = "/v1/echo/";
    const ul::Result<std::vector<uint8_t>> res =
        context_.post(echo_path, data, mimetype, params, headers);

    if (std::holds_alternative<ul::Error>(res)) {
        return res;
    }

    return ul::Result<std::vector<uint8_t>>(response_);
}

ul::Result<std::vector<uint8_t>> TestContext::upload(
    const std::string& path,
    const std::vector<ul::File>& files
) const {
    const std::string echo_path = "/v1/echo/";
    const ul::Result<std::vector<uint8_t>> res =
        context_.upload(echo_path, files);

    if (std::holds_alternative<ul::Error>(res)) {
        return res;
    }

    return ul::Result<std::vector<uint8_t>>(response_);
}

ul::Result<std::vector<uint8_t>> TestContext::del(
    const std::string& path,
    const std::map<std::string, std::string>& params,
    const std::map<std::string, std::string>& headers
) const {
    const std::string echo_path = "/v1/echo/";
    const ul::Result<std::vector<uint8_t>> res =
        context_.del(echo_path, params, headers);

    if (std::holds_alternative<ul::Error>(res)) {
        return res;
    }

    return ul::Result<std::vector<uint8_t>>(response_);
}

static arrow::Result<std::vector<std::shared_ptr<arrow::RecordBatch>>>
make_test_arrow_batches_impl(std::vector<uint8_t>& serialized) {
    std::vector<int32_t> int_vector;
    std::vector<std::string> str_vector;

    for (int i = 0; i < 20; ++i) {
        char buf[32] = {};
        std::snprintf(buf, 32, "test%d", i);

        int_vector.push_back(i);
        str_vector.push_back(std::string(buf));
    }

    std::vector<const char*> str_ptrs;
    for (int i = 0; i < 20; ++i) {
        str_ptrs.push_back(&(str_vector[i][0]));
    }

    arrow::StringBuilder str_builder;
    ARROW_RETURN_NOT_OK(str_builder.AppendValues(&str_ptrs[0], 20));
    std::shared_ptr<arrow::Array> str_array;
    ARROW_ASSIGN_OR_RAISE(str_array, str_builder.Finish());

    arrow::Int32Builder int_builder;
    ARROW_RETURN_NOT_OK(int_builder.AppendValues(&int_vector[0], 20));
    std::shared_ptr<arrow::Array> int_array;
    ARROW_ASSIGN_OR_RAISE(int_array, int_builder.Finish());

    std::shared_ptr<arrow::Field> f_v, f_i;
    f_v = arrow::field("v", arrow::utf8());
    f_i = arrow::field("i", arrow::int32());
    std::shared_ptr<arrow::Schema> schema = arrow::schema({f_v, f_i});
    std::vector<std::shared_ptr<arrow::Array>> columns = {str_array, int_array};
    std::shared_ptr<arrow::RecordBatch> batch =
        arrow::RecordBatch::Make(schema, 20, columns);

    std::vector<std::shared_ptr<arrow::RecordBatch>> batches;
    batches.push_back(batch);

    std::shared_ptr<arrow::Table> table = arrow::Table::Make(schema, columns);
    std::shared_ptr<arrow::io::BufferOutputStream> out;
    ARROW_ASSIGN_OR_RAISE(out, arrow::io::BufferOutputStream::Create());
    ARROW_ASSIGN_OR_RAISE(
        std::shared_ptr<arrow::ipc::RecordBatchWriter> ipc_writer,
        arrow::ipc::MakeStreamWriter(out, schema)
    );
    ARROW_RETURN_NOT_OK(ipc_writer->WriteTable(*table));
    ARROW_RETURN_NOT_OK(ipc_writer->Close());

    std::shared_ptr<arrow::Buffer> buffer;
    ARROW_ASSIGN_OR_RAISE(buffer, out->Finish());

    const uint8_t* data = buffer->data();
    serialized.insert(serialized.end(), data, data + buffer->size());

    return batches;
}

std::vector<std::shared_ptr<::arrow::RecordBatch>>
make_test_arrow_batches(std::vector<uint8_t>& serialized) {
    auto result = make_test_arrow_batches_impl(serialized);
    if (!result.ok()) {
        throw std::runtime_error(result.status().message());
    }

    return result.ValueOrDie();
}
