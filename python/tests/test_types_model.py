# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from ..types.model import *

def test_model():
    _t0 = Model.make_default()
    _b = _t0.to_bytes()
    _t1 = Model.from_bytes(_b)
    assert _t0 == _t1