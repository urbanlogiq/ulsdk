# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from ..types.log import *

def test_label():
    _t0 = Label.make_default()
    _b = _t0.to_bytes()
    _t1 = Label.from_bytes(_b)
    assert _t0 == _t1
def test_log():
    _t0 = Log.make_default()
    _b = _t0.to_bytes()
    _t1 = Log.from_bytes(_b)
    assert _t0 == _t1
def test_pair():
    _t0 = Pair.make_default()
    _b = _t0.to_bytes()
    _t1 = Pair.from_bytes(_b)
    assert _t0 == _t1