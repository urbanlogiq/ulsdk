# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from ..types.notification import *

def test_access_request():
    _t0 = AccessRequest.make_default()
    _b = _t0.to_bytes()
    _t1 = AccessRequest.from_bytes(_b)
    assert _t0 == _t1
def test_drive_change():
    _t0 = DriveChange.make_default()
    _b = _t0.to_bytes()
    _t1 = DriveChange.from_bytes(_b)
    assert _t0 == _t1
def test_inbox():
    _t0 = Inbox.make_default()
    _b = _t0.to_bytes()
    _t1 = Inbox.from_bytes(_b)
    assert _t0 == _t1
def test_inbox_item():
    _t0 = InboxItem.make_default()
    _b = _t0.to_bytes()
    _t1 = InboxItem.from_bytes(_b)
    assert _t0 == _t1
def test_job_complete():
    _t0 = JobComplete.make_default()
    _b = _t0.to_bytes()
    _t1 = JobComplete.from_bytes(_b)
    assert _t0 == _t1
def test_notification():
    _t0 = Notification.make_default()
    _b = _t0.to_bytes()
    _t1 = Notification.from_bytes(_b)
    assert _t0 == _t1
def test_response():
    _t0 = Response.make_default()
    _b = _t0.to_bytes()
    _t1 = Response.from_bytes(_b)
    assert _t0 == _t1
def test_share():
    _t0 = Share.make_default()
    _b = _t0.to_bytes()
    _t1 = Share.from_bytes(_b)
    assert _t0 == _t1
def test_share_details():
    _t0 = ShareDetails.make_default()
    _b = _t0.to_bytes()
    _t1 = ShareDetails.from_bytes(_b)
    assert _t0 == _t1