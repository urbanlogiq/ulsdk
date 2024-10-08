# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from ..types.job import *

def test_deprecated_run_spec():
    _t0 = DeprecatedRunSpec.make_default()
    _b = _t0.to_bytes()
    _t1 = DeprecatedRunSpec.from_bytes(_b)
    assert _t0 == _t1
def test_deprecated_task_parameter():
    _t0 = DeprecatedTaskParameter.make_default()
    _b = _t0.to_bytes()
    _t1 = DeprecatedTaskParameter.from_bytes(_b)
    assert _t0 == _t1
def test_edge():
    _t0 = Edge.make_default()
    _b = _t0.to_bytes()
    _t1 = Edge.from_bytes(_b)
    assert _t0 == _t1
def test_embedded_table():
    _t0 = EmbeddedTable.make_default()
    _b = _t0.to_bytes()
    _t1 = EmbeddedTable.from_bytes(_b)
    assert _t0 == _t1
def test_job():
    _t0 = Job.make_default()
    _b = _t0.to_bytes()
    _t1 = Job.from_bytes(_b)
    assert _t0 == _t1
def test_node():
    _t0 = Node.make_default()
    _b = _t0.to_bytes()
    _t1 = Node.from_bytes(_b)
    assert _t0 == _t1
def test_param_indices():
    _t0 = ParamIndices.make_default()
    _b = _t0.to_bytes()
    _t1 = ParamIndices.from_bytes(_b)
    assert _t0 == _t1
def test_run_spec():
    _t0 = RunSpec.make_default()
    _b = _t0.to_bytes()
    _t1 = RunSpec.from_bytes(_b)
    assert _t0 == _t1
def test_schematic():
    _t0 = Schematic.make_default()
    _b = _t0.to_bytes()
    _t1 = Schematic.from_bytes(_b)
    assert _t0 == _t1
def test_task():
    _t0 = Task.make_default()
    _b = _t0.to_bytes()
    _t1 = Task.from_bytes(_b)
    assert _t0 == _t1
def test_task_list():
    _t0 = TaskList.make_default()
    _b = _t0.to_bytes()
    _t1 = TaskList.from_bytes(_b)
    assert _t0 == _t1
def test_task_parameter():
    _t0 = TaskParameter.make_default()
    _b = _t0.to_bytes()
    _t1 = TaskParameter.from_bytes(_b)
    assert _t0 == _t1