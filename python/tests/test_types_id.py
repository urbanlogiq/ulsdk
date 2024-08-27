# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from ..types.id import *

def test_b_2c_id():
    _t0 = B2cId.make_default()
    _b = _t0.to_bytes()
    _t1 = B2cId.from_bytes(_b)
    assert _t0 == _t1
def test_column_group_id():
    _t0 = ColumnGroupId.make_default()
    _b = _t0.to_bytes()
    _t1 = ColumnGroupId.from_bytes(_b)
    assert _t0 == _t1
def test_content_id():
    _t0 = ContentId.make_default()
    _b = _t0.to_bytes()
    _t1 = ContentId.from_bytes(_b)
    assert _t0 == _t1
def test_data_state_id():
    _t0 = DataStateId.make_default()
    _b = _t0.to_bytes()
    _t1 = DataStateId.from_bytes(_b)
    assert _t0 == _t1
def test_generic_id():
    _t0 = GenericId.make_default()
    _b = _t0.to_bytes()
    _t1 = GenericId.from_bytes(_b)
    assert _t0 == _t1
def test_graph_node_id():
    _t0 = GraphNodeId.make_default()
    _b = _t0.to_bytes()
    _t1 = GraphNodeId.from_bytes(_b)
    assert _t0 == _t1
def test_object_id():
    _t0 = ObjectId.make_default()
    _b = _t0.to_bytes()
    _t1 = ObjectId.from_bytes(_b)
    assert _t0 == _t1
def test_stream_id():
    _t0 = StreamId.make_default()
    _b = _t0.to_bytes()
    _t1 = StreamId.from_bytes(_b)
    assert _t0 == _t1