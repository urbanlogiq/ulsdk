// Copyright (c), CommunityLogiq Software
// 
// THIS FILE IS AUTOGENERATED, DO NOT EDIT

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <variant>
#include <vector>

#include "flatbuffers/flatbuffers.h"
#include "ulsdk/types/id.h"
#include "ulsdk/types/permissions.h"
#include "ulsdk/types/generated/notification_generated.h"

namespace ul {
namespace types {

struct AccessRequest;
struct DriveChange;
struct Inbox;
struct InboxItem;
struct JobComplete;
struct Notification;
struct Response;
struct Share;
struct ShareDetails;

using ::DriveAction;
typedef std::variant<
    std::shared_ptr<Share>,
    std::shared_ptr<JobComplete>,
    std::shared_ptr<AccessRequest>,
    std::shared_ptr<DriveChange>
> NotificationUnion;

using ::ReadStatus;
using ::RequestStatus;
struct Share {
    std::optional<std::string> dest_;
    std::optional<std::string> msg_;
    PermissionTy new_perms_;
    ObjectId object_;
    PermissionTy old_perms_;

    Share();
    Share(const ::Share *root);
    Share(const std::vector<uint8_t> &bytes);
};

struct JobComplete {
    ObjectId job_;

    JobComplete();
    JobComplete(const ::JobComplete *root);
    JobComplete(const std::vector<uint8_t> &bytes);
};

struct AccessRequest {
    std::optional<std::string> msg_;
    ObjectId object_;
    uint32_t perms_;
    uint32_t requested_ownership_;
    RequestStatus status_;

    AccessRequest();
    AccessRequest(const ::AccessRequest *root);
    AccessRequest(const std::vector<uint8_t> &bytes);
};

struct DriveChange {
    DriveAction action_;
    ObjectId object_;
    ObjectId root_;

    DriveChange();
    DriveChange(const ::DriveChange *root);
    DriveChange(const std::vector<uint8_t> &bytes);
};

struct Inbox {
    std::vector<InboxItem> items_;

    Inbox();
    Inbox(const ::Inbox *root);
    Inbox(const std::vector<uint8_t> &bytes);
};

struct InboxItem {
    ObjectId notification_;
    ReadStatus status_;
    uint64_t time_;

    InboxItem();
    InboxItem(const ::InboxItem *root);
    InboxItem(const std::vector<uint8_t> &bytes);
};

struct Notification {
    std::optional<NotificationUnion> notification_;
    std::optional<B2cId> sender_;

    Notification();
    Notification(const ::Notification *root);
    Notification(const std::vector<uint8_t> &bytes);
};

struct Response {
    std::optional<std::string> msg_;

    Response();
    Response(const ::Response *root);
    Response(const std::vector<uint8_t> &bytes);
};

struct ShareDetails {
    std::optional<std::string> msg_;
    bool notify_;

    ShareDetails();
    ShareDetails(const ::ShareDetails *root);
    ShareDetails(const std::vector<uint8_t> &bytes);
};

std::pair<::flatbuffers::Offset<void>, ::NotificationUnion>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const NotificationUnion &o);
::flatbuffers::Offset<::Share>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Share &);

::flatbuffers::Offset<::JobComplete>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const JobComplete &);

::flatbuffers::Offset<::AccessRequest>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const AccessRequest &);

::flatbuffers::Offset<::DriveChange>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const DriveChange &);

::flatbuffers::Offset<::Inbox>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Inbox &);

::flatbuffers::Offset<::InboxItem>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const InboxItem &);

::flatbuffers::Offset<::Notification>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Notification &);

::flatbuffers::Offset<::Response>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Response &);

::flatbuffers::Offset<::ShareDetails>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const ShareDetails &);


std::vector<uint8_t>
to_bytes(const Share &o);

std::vector<uint8_t>
to_bytes(const JobComplete &o);

std::vector<uint8_t>
to_bytes(const AccessRequest &o);

std::vector<uint8_t>
to_bytes(const DriveChange &o);

std::vector<uint8_t>
to_bytes(const Inbox &o);

std::vector<uint8_t>
to_bytes(const InboxItem &o);

std::vector<uint8_t>
to_bytes(const Notification &o);

std::vector<uint8_t>
to_bytes(const Response &o);

std::vector<uint8_t>
to_bytes(const ShareDetails &o);


} // namespace types
} // namespace ul
