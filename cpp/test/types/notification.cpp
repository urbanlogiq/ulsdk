// Copyright (c), CommunityLogiq Software
// 
// THIS FILE IS AUTOGENERATED, DO NOT EDIT

#include "ulsdk/types/notification.h"

#include "test.h"

bool
test_access_request() {
    ::ul::types::AccessRequest t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::AccessRequest deserialized = ::ul::types::AccessRequest(bytes);
    return true;
}

TypeTest test_access_request_obj(test_access_request, "AccessRequest");

bool
test_drive_change() {
    ::ul::types::DriveChange t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::DriveChange deserialized = ::ul::types::DriveChange(bytes);
    return true;
}

TypeTest test_drive_change_obj(test_drive_change, "DriveChange");

bool
test_inbox() {
    ::ul::types::Inbox t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Inbox deserialized = ::ul::types::Inbox(bytes);
    return true;
}

TypeTest test_inbox_obj(test_inbox, "Inbox");

bool
test_inbox_item() {
    ::ul::types::InboxItem t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::InboxItem deserialized = ::ul::types::InboxItem(bytes);
    return true;
}

TypeTest test_inbox_item_obj(test_inbox_item, "InboxItem");

bool
test_job_complete() {
    ::ul::types::JobComplete t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::JobComplete deserialized = ::ul::types::JobComplete(bytes);
    return true;
}

TypeTest test_job_complete_obj(test_job_complete, "JobComplete");

bool
test_notification() {
    ::ul::types::Notification t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Notification deserialized = ::ul::types::Notification(bytes);
    return true;
}

TypeTest test_notification_obj(test_notification, "Notification");

bool
test_response() {
    ::ul::types::Response t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Response deserialized = ::ul::types::Response(bytes);
    return true;
}

TypeTest test_response_obj(test_response, "Response");

bool
test_share() {
    ::ul::types::Share t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Share deserialized = ::ul::types::Share(bytes);
    return true;
}

TypeTest test_share_obj(test_share, "Share");

bool
test_share_details() {
    ::ul::types::ShareDetails t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::ShareDetails deserialized = ::ul::types::ShareDetails(bytes);
    return true;
}

TypeTest test_share_details_obj(test_share_details, "ShareDetails");
