# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

import os
from ..api_key_context import ApiKeyContext
from ..keys import Region, Key as SigningKey, Environment
from ..api.acl import *

def test_new_acl():

    if False:
        new_acl(
            ctx,
        )

def test_new_from():
    p0 = None

    if False:
        new_from(
            ctx,
            p0,
        )

def test_request():
    p0 = AccessRequest.make_default()

    if False:
        request(
            ctx,
            p0,
        )

def test_share():
    p0 = UUID("00000000-0000-0000-0000-000000000000")
    p1 = UUID("00000000-0000-0000-0000-000000000000")
    p2 = 0

    if False:
        share(
            ctx,
            p0,
            p1,
            p2,
        )

def test_share_with_details():
    p0 = UUID("00000000-0000-0000-0000-000000000000")
    p1 = UUID("00000000-0000-0000-0000-000000000000")
    p2 = 0
    p3 = ShareDetails.make_default()

    if False:
        share_with_details(
            ctx,
            p0,
            p1,
            p2,
            p3,
        )

def test_share_all():
    p0 = UUID("00000000-0000-0000-0000-000000000000")
    p1 = UUID("00000000-0000-0000-0000-000000000000")

    if False:
        share_all(
            ctx,
            p0,
            p1,
        )

def test_share_all_with_details():
    p0 = UUID("00000000-0000-0000-0000-000000000000")
    p1 = UUID("00000000-0000-0000-0000-000000000000")
    p2 = ShareDetails.make_default()

    if False:
        share_all_with_details(
            ctx,
            p0,
            p1,
            p2,
        )

def test_grant():
    p0 = UUID("00000000-0000-0000-0000-000000000000")
    p1 = UUID("00000000-0000-0000-0000-000000000000")
    p2 = 0

    if False:
        grant(
            ctx,
            p0,
            p1,
            p2,
        )

def test_grant_with_details():
    p0 = UUID("00000000-0000-0000-0000-000000000000")
    p1 = UUID("00000000-0000-0000-0000-000000000000")
    p2 = 0
    p3 = ShareDetails.make_default()

    if False:
        grant_with_details(
            ctx,
            p0,
            p1,
            p2,
            p3,
        )

def test_grant_all():
    p0 = UUID("00000000-0000-0000-0000-000000000000")
    p1 = UUID("00000000-0000-0000-0000-000000000000")

    if False:
        grant_all(
            ctx,
            p0,
            p1,
        )

def test_grant_all_with_details():
    p0 = UUID("00000000-0000-0000-0000-000000000000")
    p1 = UUID("00000000-0000-0000-0000-000000000000")
    p2 = ShareDetails.make_default()

    if False:
        grant_all_with_details(
            ctx,
            p0,
            p1,
            p2,
        )

def test_revoke():
    p0 = UUID("00000000-0000-0000-0000-000000000000")
    p1 = UUID("00000000-0000-0000-0000-000000000000")

    if False:
        revoke(
            ctx,
            p0,
            p1,
        )

def test_get_permissions():
    p0 = UUID("00000000-0000-0000-0000-000000000000")

    if False:
        get_permissions(
            ctx,
            p0,
        )

def test_set():
    p0 = UUID("00000000-0000-0000-0000-000000000000")
    p1 = UUID("00000000-0000-0000-0000-000000000000")

    if False:
        set(
            ctx,
            p0,
            p1,
        )
