# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from ..types.stream import *

def test_stream():
    _t0 = Stream.make_default()
    _b = _t0.to_bytes()
    _t1 = Stream.from_bytes(_b)
    assert _t0 == _t1