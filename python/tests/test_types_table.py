# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from ..types.table import *

def test_change_op_entry():
    _t0 = ChangeOpEntry.make_default()
    _b = _t0.to_bytes()
    _t1 = ChangeOpEntry.from_bytes(_b)
    assert _t0 == _t1
def test_change_set():
    _t0 = ChangeSet.make_default()
    _b = _t0.to_bytes()
    _t1 = ChangeSet.from_bytes(_b)
    assert _t0 == _t1
def test_delete():
    _t0 = Delete.make_default()
    _b = _t0.to_bytes()
    _t1 = Delete.from_bytes(_b)
    assert _t0 == _t1
def test_diff_stream():
    _t0 = DiffStream.make_default()
    _b = _t0.to_bytes()
    _t1 = DiffStream.from_bytes(_b)
    assert _t0 == _t1
def test_history():
    _t0 = History.make_default()
    _b = _t0.to_bytes()
    _t1 = History.from_bytes(_b)
    assert _t0 == _t1
def test_modify():
    _t0 = Modify.make_default()
    _b = _t0.to_bytes()
    _t1 = Modify.from_bytes(_b)
    assert _t0 == _t1
def test_new_table():
    _t0 = NewTable.make_default()
    _b = _t0.to_bytes()
    _t1 = NewTable.from_bytes(_b)
    assert _t0 == _t1
def test_op_entry():
    _t0 = OpEntry.make_default()
    _b = _t0.to_bytes()
    _t1 = OpEntry.from_bytes(_b)
    assert _t0 == _t1
def test_restore():
    _t0 = Restore.make_default()
    _b = _t0.to_bytes()
    _t1 = Restore.from_bytes(_b)
    assert _t0 == _t1
def test_restore_row():
    _t0 = RestoreRow.make_default()
    _b = _t0.to_bytes()
    _t1 = RestoreRow.from_bytes(_b)
    assert _t0 == _t1
def test_rm_row():
    _t0 = RmRow.make_default()
    _b = _t0.to_bytes()
    _t1 = RmRow.from_bytes(_b)
    assert _t0 == _t1
def test_set():
    _t0 = Set.make_default()
    _b = _t0.to_bytes()
    _t1 = Set.from_bytes(_b)
    assert _t0 == _t1