// Copyright (c), CommunityLogiq Software
// 
// THIS FILE IS AUTOGENERATED, DO NOT EDIT

#include "ulsdk/types/job.h"

#include "test.h"

bool
test_deprecated_run_spec() {
    ::ul::types::DeprecatedRunSpec t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::DeprecatedRunSpec deserialized = ::ul::types::DeprecatedRunSpec(bytes);
    return true;
}

TypeTest test_deprecated_run_spec_obj(test_deprecated_run_spec, "DeprecatedRunSpec");

bool
test_deprecated_task_parameter() {
    ::ul::types::DeprecatedTaskParameter t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::DeprecatedTaskParameter deserialized = ::ul::types::DeprecatedTaskParameter(bytes);
    return true;
}

TypeTest test_deprecated_task_parameter_obj(test_deprecated_task_parameter, "DeprecatedTaskParameter");

bool
test_edge() {
    ::ul::types::Edge t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Edge deserialized = ::ul::types::Edge(bytes);
    return true;
}

TypeTest test_edge_obj(test_edge, "Edge");

bool
test_embedded_table() {
    ::ul::types::EmbeddedTable t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::EmbeddedTable deserialized = ::ul::types::EmbeddedTable(bytes);
    return true;
}

TypeTest test_embedded_table_obj(test_embedded_table, "EmbeddedTable");

bool
test_job() {
    ::ul::types::Job t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Job deserialized = ::ul::types::Job(bytes);
    return true;
}

TypeTest test_job_obj(test_job, "Job");

bool
test_node() {
    ::ul::types::Node t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Node deserialized = ::ul::types::Node(bytes);
    return true;
}

TypeTest test_node_obj(test_node, "Node");

bool
test_param_indices() {
    ::ul::types::ParamIndices t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::ParamIndices deserialized = ::ul::types::ParamIndices(bytes);
    return true;
}

TypeTest test_param_indices_obj(test_param_indices, "ParamIndices");

bool
test_run_spec() {
    ::ul::types::RunSpec t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::RunSpec deserialized = ::ul::types::RunSpec(bytes);
    return true;
}

TypeTest test_run_spec_obj(test_run_spec, "RunSpec");

bool
test_schematic() {
    ::ul::types::Schematic t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Schematic deserialized = ::ul::types::Schematic(bytes);
    return true;
}

TypeTest test_schematic_obj(test_schematic, "Schematic");

bool
test_task() {
    ::ul::types::Task t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Task deserialized = ::ul::types::Task(bytes);
    return true;
}

TypeTest test_task_obj(test_task, "Task");

bool
test_task_list() {
    ::ul::types::TaskList t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::TaskList deserialized = ::ul::types::TaskList(bytes);
    return true;
}

TypeTest test_task_list_obj(test_task_list, "TaskList");

bool
test_task_parameter() {
    ::ul::types::TaskParameter t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::TaskParameter deserialized = ::ul::types::TaskParameter(bytes);
    return true;
}

TypeTest test_task_parameter_obj(test_task_parameter, "TaskParameter");