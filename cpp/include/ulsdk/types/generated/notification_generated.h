// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_NOTIFICATION_H_
#define FLATBUFFERS_GENERATED_NOTIFICATION_H_

#include "flatbuffers/flatbuffers.h"

// Ensure the included flatbuffers.h is the same version as when this file was
// generated, otherwise it may not be compatible.
static_assert(FLATBUFFERS_VERSION_MAJOR == 23 &&
              FLATBUFFERS_VERSION_MINOR == 5 &&
              FLATBUFFERS_VERSION_REVISION == 26,
             "Non-compatible flatbuffers version included");

#include "id_generated.h"
#include "permissions_generated.h"

struct Response;
struct ResponseBuilder;

struct AccessRequest;
struct AccessRequestBuilder;

struct Share;
struct ShareBuilder;

struct JobComplete;
struct JobCompleteBuilder;

struct DriveChange;
struct DriveChangeBuilder;

struct Notification;
struct NotificationBuilder;

struct ShareDetails;
struct ShareDetailsBuilder;

struct InboxItem;
struct InboxItemBuilder;

struct Inbox;
struct InboxBuilder;

enum class ReadStatus : uint8_t {
  Unread = 0,
  Read = 1,
  MIN = Unread,
  MAX = Read
};

inline const ReadStatus (&EnumValuesReadStatus())[2] {
  static const ReadStatus values[] = {
    ReadStatus::Unread,
    ReadStatus::Read
  };
  return values;
}

inline const char * const *EnumNamesReadStatus() {
  static const char * const names[3] = {
    "Unread",
    "Read",
    nullptr
  };
  return names;
}

inline const char *EnumNameReadStatus(ReadStatus e) {
  if (::flatbuffers::IsOutRange(e, ReadStatus::Unread, ReadStatus::Read)) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesReadStatus()[index];
}

enum class RequestStatus : uint8_t {
  Pending = 0,
  Approved = 1,
  Rejected = 2,
  MIN = Pending,
  MAX = Rejected
};

inline const RequestStatus (&EnumValuesRequestStatus())[3] {
  static const RequestStatus values[] = {
    RequestStatus::Pending,
    RequestStatus::Approved,
    RequestStatus::Rejected
  };
  return values;
}

inline const char * const *EnumNamesRequestStatus() {
  static const char * const names[4] = {
    "Pending",
    "Approved",
    "Rejected",
    nullptr
  };
  return names;
}

inline const char *EnumNameRequestStatus(RequestStatus e) {
  if (::flatbuffers::IsOutRange(e, RequestStatus::Pending, RequestStatus::Rejected)) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesRequestStatus()[index];
}

enum class DriveAction : uint8_t {
  Add = 0,
  Remove = 1,
  Overwrite = 2,
  MIN = Add,
  MAX = Overwrite
};

inline const DriveAction (&EnumValuesDriveAction())[3] {
  static const DriveAction values[] = {
    DriveAction::Add,
    DriveAction::Remove,
    DriveAction::Overwrite
  };
  return values;
}

inline const char * const *EnumNamesDriveAction() {
  static const char * const names[4] = {
    "Add",
    "Remove",
    "Overwrite",
    nullptr
  };
  return names;
}

inline const char *EnumNameDriveAction(DriveAction e) {
  if (::flatbuffers::IsOutRange(e, DriveAction::Add, DriveAction::Overwrite)) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesDriveAction()[index];
}

enum class NotificationUnion : uint8_t {
  NONE = 0,
  Share = 1,
  JobComplete = 2,
  AccessRequest = 3,
  DriveChange = 4,
  MIN = NONE,
  MAX = DriveChange
};

inline const NotificationUnion (&EnumValuesNotificationUnion())[5] {
  static const NotificationUnion values[] = {
    NotificationUnion::NONE,
    NotificationUnion::Share,
    NotificationUnion::JobComplete,
    NotificationUnion::AccessRequest,
    NotificationUnion::DriveChange
  };
  return values;
}

inline const char * const *EnumNamesNotificationUnion() {
  static const char * const names[6] = {
    "NONE",
    "Share",
    "JobComplete",
    "AccessRequest",
    "DriveChange",
    nullptr
  };
  return names;
}

inline const char *EnumNameNotificationUnion(NotificationUnion e) {
  if (::flatbuffers::IsOutRange(e, NotificationUnion::NONE, NotificationUnion::DriveChange)) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesNotificationUnion()[index];
}

template<typename T> struct NotificationUnionTraits {
  static const NotificationUnion enum_value = NotificationUnion::NONE;
};

template<> struct NotificationUnionTraits<Share> {
  static const NotificationUnion enum_value = NotificationUnion::Share;
};

template<> struct NotificationUnionTraits<JobComplete> {
  static const NotificationUnion enum_value = NotificationUnion::JobComplete;
};

template<> struct NotificationUnionTraits<AccessRequest> {
  static const NotificationUnion enum_value = NotificationUnion::AccessRequest;
};

template<> struct NotificationUnionTraits<DriveChange> {
  static const NotificationUnion enum_value = NotificationUnion::DriveChange;
};

bool VerifyNotificationUnion(::flatbuffers::Verifier &verifier, const void *obj, NotificationUnion type);
bool VerifyNotificationUnionVector(::flatbuffers::Verifier &verifier, const ::flatbuffers::Vector<::flatbuffers::Offset<void>> *values, const ::flatbuffers::Vector<NotificationUnion> *types);

struct Response FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef ResponseBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_MSG = 4
  };
  const ::flatbuffers::String *msg() const {
    return GetPointer<const ::flatbuffers::String *>(VT_MSG);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_MSG) &&
           verifier.VerifyString(msg()) &&
           verifier.EndTable();
  }
};

struct ResponseBuilder {
  typedef Response Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_msg(::flatbuffers::Offset<::flatbuffers::String> msg) {
    fbb_.AddOffset(Response::VT_MSG, msg);
  }
  explicit ResponseBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<Response> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<Response>(end);
    return o;
  }
};

inline ::flatbuffers::Offset<Response> CreateResponse(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<::flatbuffers::String> msg = 0) {
  ResponseBuilder builder_(_fbb);
  builder_.add_msg(msg);
  return builder_.Finish();
}

struct Response::Traits {
  using type = Response;
  static auto constexpr Create = CreateResponse;
};

inline ::flatbuffers::Offset<Response> CreateResponseDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    const char *msg = nullptr) {
  auto msg__ = msg ? _fbb.CreateString(msg) : 0;
  return CreateResponse(
      _fbb,
      msg__);
}

struct AccessRequest FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef AccessRequestBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_OBJECT = 4,
    VT_PERMS = 6,
    VT_STATUS = 8,
    VT_MSG = 10,
    VT_REQUESTED_OWNERSHIP = 12
  };
  const ObjectId *object() const {
    return GetPointer<const ObjectId *>(VT_OBJECT);
  }
  uint32_t perms() const {
    return GetField<uint32_t>(VT_PERMS, 0);
  }
  RequestStatus status() const {
    return static_cast<RequestStatus>(GetField<uint8_t>(VT_STATUS, 0));
  }
  const ::flatbuffers::String *msg() const {
    return GetPointer<const ::flatbuffers::String *>(VT_MSG);
  }
  uint32_t requested_ownership() const {
    return GetField<uint32_t>(VT_REQUESTED_OWNERSHIP, 0);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_OBJECT) &&
           verifier.VerifyTable(object()) &&
           VerifyField<uint32_t>(verifier, VT_PERMS, 4) &&
           VerifyField<uint8_t>(verifier, VT_STATUS, 1) &&
           VerifyOffset(verifier, VT_MSG) &&
           verifier.VerifyString(msg()) &&
           VerifyField<uint32_t>(verifier, VT_REQUESTED_OWNERSHIP, 4) &&
           verifier.EndTable();
  }
};

struct AccessRequestBuilder {
  typedef AccessRequest Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_object(::flatbuffers::Offset<ObjectId> object) {
    fbb_.AddOffset(AccessRequest::VT_OBJECT, object);
  }
  void add_perms(uint32_t perms) {
    fbb_.AddElement<uint32_t>(AccessRequest::VT_PERMS, perms, 0);
  }
  void add_status(RequestStatus status) {
    fbb_.AddElement<uint8_t>(AccessRequest::VT_STATUS, static_cast<uint8_t>(status), 0);
  }
  void add_msg(::flatbuffers::Offset<::flatbuffers::String> msg) {
    fbb_.AddOffset(AccessRequest::VT_MSG, msg);
  }
  void add_requested_ownership(uint32_t requested_ownership) {
    fbb_.AddElement<uint32_t>(AccessRequest::VT_REQUESTED_OWNERSHIP, requested_ownership, 0);
  }
  explicit AccessRequestBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<AccessRequest> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<AccessRequest>(end);
    fbb_.Required(o, AccessRequest::VT_OBJECT);
    return o;
  }
};

inline ::flatbuffers::Offset<AccessRequest> CreateAccessRequest(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<ObjectId> object = 0,
    uint32_t perms = 0,
    RequestStatus status = RequestStatus::Pending,
    ::flatbuffers::Offset<::flatbuffers::String> msg = 0,
    uint32_t requested_ownership = 0) {
  AccessRequestBuilder builder_(_fbb);
  builder_.add_requested_ownership(requested_ownership);
  builder_.add_msg(msg);
  builder_.add_perms(perms);
  builder_.add_object(object);
  builder_.add_status(status);
  return builder_.Finish();
}

struct AccessRequest::Traits {
  using type = AccessRequest;
  static auto constexpr Create = CreateAccessRequest;
};

inline ::flatbuffers::Offset<AccessRequest> CreateAccessRequestDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<ObjectId> object = 0,
    uint32_t perms = 0,
    RequestStatus status = RequestStatus::Pending,
    const char *msg = nullptr,
    uint32_t requested_ownership = 0) {
  auto msg__ = msg ? _fbb.CreateString(msg) : 0;
  return CreateAccessRequest(
      _fbb,
      object,
      perms,
      status,
      msg__,
      requested_ownership);
}

struct Share FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef ShareBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_OBJECT = 4,
    VT_DEST = 6,
    VT_MSG = 8,
    VT_OLD_PERMS = 10,
    VT_NEW_PERMS = 12
  };
  const ObjectId *object() const {
    return GetPointer<const ObjectId *>(VT_OBJECT);
  }
  const ::flatbuffers::String *dest() const {
    return GetPointer<const ::flatbuffers::String *>(VT_DEST);
  }
  const ::flatbuffers::String *msg() const {
    return GetPointer<const ::flatbuffers::String *>(VT_MSG);
  }
  PermissionTy old_perms() const {
    return static_cast<PermissionTy>(GetField<uint32_t>(VT_OLD_PERMS, 0));
  }
  PermissionTy new_perms() const {
    return static_cast<PermissionTy>(GetField<uint32_t>(VT_NEW_PERMS, 0));
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_OBJECT) &&
           verifier.VerifyTable(object()) &&
           VerifyOffset(verifier, VT_DEST) &&
           verifier.VerifyString(dest()) &&
           VerifyOffset(verifier, VT_MSG) &&
           verifier.VerifyString(msg()) &&
           VerifyField<uint32_t>(verifier, VT_OLD_PERMS, 4) &&
           VerifyField<uint32_t>(verifier, VT_NEW_PERMS, 4) &&
           verifier.EndTable();
  }
};

struct ShareBuilder {
  typedef Share Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_object(::flatbuffers::Offset<ObjectId> object) {
    fbb_.AddOffset(Share::VT_OBJECT, object);
  }
  void add_dest(::flatbuffers::Offset<::flatbuffers::String> dest) {
    fbb_.AddOffset(Share::VT_DEST, dest);
  }
  void add_msg(::flatbuffers::Offset<::flatbuffers::String> msg) {
    fbb_.AddOffset(Share::VT_MSG, msg);
  }
  void add_old_perms(PermissionTy old_perms) {
    fbb_.AddElement<uint32_t>(Share::VT_OLD_PERMS, static_cast<uint32_t>(old_perms), 0);
  }
  void add_new_perms(PermissionTy new_perms) {
    fbb_.AddElement<uint32_t>(Share::VT_NEW_PERMS, static_cast<uint32_t>(new_perms), 0);
  }
  explicit ShareBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<Share> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<Share>(end);
    fbb_.Required(o, Share::VT_OBJECT);
    return o;
  }
};

inline ::flatbuffers::Offset<Share> CreateShare(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<ObjectId> object = 0,
    ::flatbuffers::Offset<::flatbuffers::String> dest = 0,
    ::flatbuffers::Offset<::flatbuffers::String> msg = 0,
    PermissionTy old_perms = static_cast<PermissionTy>(0),
    PermissionTy new_perms = static_cast<PermissionTy>(0)) {
  ShareBuilder builder_(_fbb);
  builder_.add_new_perms(new_perms);
  builder_.add_old_perms(old_perms);
  builder_.add_msg(msg);
  builder_.add_dest(dest);
  builder_.add_object(object);
  return builder_.Finish();
}

struct Share::Traits {
  using type = Share;
  static auto constexpr Create = CreateShare;
};

inline ::flatbuffers::Offset<Share> CreateShareDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<ObjectId> object = 0,
    const char *dest = nullptr,
    const char *msg = nullptr,
    PermissionTy old_perms = static_cast<PermissionTy>(0),
    PermissionTy new_perms = static_cast<PermissionTy>(0)) {
  auto dest__ = dest ? _fbb.CreateString(dest) : 0;
  auto msg__ = msg ? _fbb.CreateString(msg) : 0;
  return CreateShare(
      _fbb,
      object,
      dest__,
      msg__,
      old_perms,
      new_perms);
}

struct JobComplete FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef JobCompleteBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_JOB = 4
  };
  const ObjectId *job() const {
    return GetPointer<const ObjectId *>(VT_JOB);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_JOB) &&
           verifier.VerifyTable(job()) &&
           verifier.EndTable();
  }
};

struct JobCompleteBuilder {
  typedef JobComplete Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_job(::flatbuffers::Offset<ObjectId> job) {
    fbb_.AddOffset(JobComplete::VT_JOB, job);
  }
  explicit JobCompleteBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<JobComplete> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<JobComplete>(end);
    fbb_.Required(o, JobComplete::VT_JOB);
    return o;
  }
};

inline ::flatbuffers::Offset<JobComplete> CreateJobComplete(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<ObjectId> job = 0) {
  JobCompleteBuilder builder_(_fbb);
  builder_.add_job(job);
  return builder_.Finish();
}

struct JobComplete::Traits {
  using type = JobComplete;
  static auto constexpr Create = CreateJobComplete;
};

struct DriveChange FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef DriveChangeBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_ROOT = 4,
    VT_OBJECT = 6,
    VT_ACTION = 8
  };
  const ObjectId *root() const {
    return GetPointer<const ObjectId *>(VT_ROOT);
  }
  const ObjectId *object() const {
    return GetPointer<const ObjectId *>(VT_OBJECT);
  }
  DriveAction action() const {
    return static_cast<DriveAction>(GetField<uint8_t>(VT_ACTION, 0));
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_ROOT) &&
           verifier.VerifyTable(root()) &&
           VerifyOffsetRequired(verifier, VT_OBJECT) &&
           verifier.VerifyTable(object()) &&
           VerifyField<uint8_t>(verifier, VT_ACTION, 1) &&
           verifier.EndTable();
  }
};

struct DriveChangeBuilder {
  typedef DriveChange Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_root(::flatbuffers::Offset<ObjectId> root) {
    fbb_.AddOffset(DriveChange::VT_ROOT, root);
  }
  void add_object(::flatbuffers::Offset<ObjectId> object) {
    fbb_.AddOffset(DriveChange::VT_OBJECT, object);
  }
  void add_action(DriveAction action) {
    fbb_.AddElement<uint8_t>(DriveChange::VT_ACTION, static_cast<uint8_t>(action), 0);
  }
  explicit DriveChangeBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<DriveChange> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<DriveChange>(end);
    fbb_.Required(o, DriveChange::VT_ROOT);
    fbb_.Required(o, DriveChange::VT_OBJECT);
    return o;
  }
};

inline ::flatbuffers::Offset<DriveChange> CreateDriveChange(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<ObjectId> root = 0,
    ::flatbuffers::Offset<ObjectId> object = 0,
    DriveAction action = DriveAction::Add) {
  DriveChangeBuilder builder_(_fbb);
  builder_.add_object(object);
  builder_.add_root(root);
  builder_.add_action(action);
  return builder_.Finish();
}

struct DriveChange::Traits {
  using type = DriveChange;
  static auto constexpr Create = CreateDriveChange;
};

struct Notification FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef NotificationBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_SENDER = 4,
    VT_NOTIFICATION_TYPE = 6,
    VT_NOTIFICATION = 8
  };
  const B2cId *sender() const {
    return GetPointer<const B2cId *>(VT_SENDER);
  }
  NotificationUnion notification_type() const {
    return static_cast<NotificationUnion>(GetField<uint8_t>(VT_NOTIFICATION_TYPE, 0));
  }
  const void *notification() const {
    return GetPointer<const void *>(VT_NOTIFICATION);
  }
  template<typename T> const T *notification_as() const;
  const Share *notification_as_Share() const {
    return notification_type() == NotificationUnion::Share ? static_cast<const Share *>(notification()) : nullptr;
  }
  const JobComplete *notification_as_JobComplete() const {
    return notification_type() == NotificationUnion::JobComplete ? static_cast<const JobComplete *>(notification()) : nullptr;
  }
  const AccessRequest *notification_as_AccessRequest() const {
    return notification_type() == NotificationUnion::AccessRequest ? static_cast<const AccessRequest *>(notification()) : nullptr;
  }
  const DriveChange *notification_as_DriveChange() const {
    return notification_type() == NotificationUnion::DriveChange ? static_cast<const DriveChange *>(notification()) : nullptr;
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_SENDER) &&
           verifier.VerifyTable(sender()) &&
           VerifyField<uint8_t>(verifier, VT_NOTIFICATION_TYPE, 1) &&
           VerifyOffset(verifier, VT_NOTIFICATION) &&
           VerifyNotificationUnion(verifier, notification(), notification_type()) &&
           verifier.EndTable();
  }
};

template<> inline const Share *Notification::notification_as<Share>() const {
  return notification_as_Share();
}

template<> inline const JobComplete *Notification::notification_as<JobComplete>() const {
  return notification_as_JobComplete();
}

template<> inline const AccessRequest *Notification::notification_as<AccessRequest>() const {
  return notification_as_AccessRequest();
}

template<> inline const DriveChange *Notification::notification_as<DriveChange>() const {
  return notification_as_DriveChange();
}

struct NotificationBuilder {
  typedef Notification Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_sender(::flatbuffers::Offset<B2cId> sender) {
    fbb_.AddOffset(Notification::VT_SENDER, sender);
  }
  void add_notification_type(NotificationUnion notification_type) {
    fbb_.AddElement<uint8_t>(Notification::VT_NOTIFICATION_TYPE, static_cast<uint8_t>(notification_type), 0);
  }
  void add_notification(::flatbuffers::Offset<void> notification) {
    fbb_.AddOffset(Notification::VT_NOTIFICATION, notification);
  }
  explicit NotificationBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<Notification> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<Notification>(end);
    return o;
  }
};

inline ::flatbuffers::Offset<Notification> CreateNotification(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<B2cId> sender = 0,
    NotificationUnion notification_type = NotificationUnion::NONE,
    ::flatbuffers::Offset<void> notification = 0) {
  NotificationBuilder builder_(_fbb);
  builder_.add_notification(notification);
  builder_.add_sender(sender);
  builder_.add_notification_type(notification_type);
  return builder_.Finish();
}

struct Notification::Traits {
  using type = Notification;
  static auto constexpr Create = CreateNotification;
};

struct ShareDetails FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef ShareDetailsBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_NOTIFY = 4,
    VT_MSG = 6
  };
  bool notify() const {
    return GetField<uint8_t>(VT_NOTIFY, 0) != 0;
  }
  const ::flatbuffers::String *msg() const {
    return GetPointer<const ::flatbuffers::String *>(VT_MSG);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<uint8_t>(verifier, VT_NOTIFY, 1) &&
           VerifyOffset(verifier, VT_MSG) &&
           verifier.VerifyString(msg()) &&
           verifier.EndTable();
  }
};

struct ShareDetailsBuilder {
  typedef ShareDetails Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_notify(bool notify) {
    fbb_.AddElement<uint8_t>(ShareDetails::VT_NOTIFY, static_cast<uint8_t>(notify), 0);
  }
  void add_msg(::flatbuffers::Offset<::flatbuffers::String> msg) {
    fbb_.AddOffset(ShareDetails::VT_MSG, msg);
  }
  explicit ShareDetailsBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<ShareDetails> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<ShareDetails>(end);
    return o;
  }
};

inline ::flatbuffers::Offset<ShareDetails> CreateShareDetails(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    bool notify = false,
    ::flatbuffers::Offset<::flatbuffers::String> msg = 0) {
  ShareDetailsBuilder builder_(_fbb);
  builder_.add_msg(msg);
  builder_.add_notify(notify);
  return builder_.Finish();
}

struct ShareDetails::Traits {
  using type = ShareDetails;
  static auto constexpr Create = CreateShareDetails;
};

inline ::flatbuffers::Offset<ShareDetails> CreateShareDetailsDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    bool notify = false,
    const char *msg = nullptr) {
  auto msg__ = msg ? _fbb.CreateString(msg) : 0;
  return CreateShareDetails(
      _fbb,
      notify,
      msg__);
}

struct InboxItem FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef InboxItemBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_NOTIFICATION = 4,
    VT_STATUS = 6,
    VT_TIME = 8
  };
  const ObjectId *notification() const {
    return GetPointer<const ObjectId *>(VT_NOTIFICATION);
  }
  ReadStatus status() const {
    return static_cast<ReadStatus>(GetField<uint8_t>(VT_STATUS, 0));
  }
  uint64_t time() const {
    return GetField<uint64_t>(VT_TIME, 0);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_NOTIFICATION) &&
           verifier.VerifyTable(notification()) &&
           VerifyField<uint8_t>(verifier, VT_STATUS, 1) &&
           VerifyField<uint64_t>(verifier, VT_TIME, 8) &&
           verifier.EndTable();
  }
};

struct InboxItemBuilder {
  typedef InboxItem Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_notification(::flatbuffers::Offset<ObjectId> notification) {
    fbb_.AddOffset(InboxItem::VT_NOTIFICATION, notification);
  }
  void add_status(ReadStatus status) {
    fbb_.AddElement<uint8_t>(InboxItem::VT_STATUS, static_cast<uint8_t>(status), 0);
  }
  void add_time(uint64_t time) {
    fbb_.AddElement<uint64_t>(InboxItem::VT_TIME, time, 0);
  }
  explicit InboxItemBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<InboxItem> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<InboxItem>(end);
    fbb_.Required(o, InboxItem::VT_NOTIFICATION);
    return o;
  }
};

inline ::flatbuffers::Offset<InboxItem> CreateInboxItem(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<ObjectId> notification = 0,
    ReadStatus status = ReadStatus::Unread,
    uint64_t time = 0) {
  InboxItemBuilder builder_(_fbb);
  builder_.add_time(time);
  builder_.add_notification(notification);
  builder_.add_status(status);
  return builder_.Finish();
}

struct InboxItem::Traits {
  using type = InboxItem;
  static auto constexpr Create = CreateInboxItem;
};

struct Inbox FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef InboxBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_ITEMS = 4
  };
  const ::flatbuffers::Vector<::flatbuffers::Offset<InboxItem>> *items() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<InboxItem>> *>(VT_ITEMS);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_ITEMS) &&
           verifier.VerifyVector(items()) &&
           verifier.VerifyVectorOfTables(items()) &&
           verifier.EndTable();
  }
};

struct InboxBuilder {
  typedef Inbox Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_items(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<InboxItem>>> items) {
    fbb_.AddOffset(Inbox::VT_ITEMS, items);
  }
  explicit InboxBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<Inbox> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<Inbox>(end);
    fbb_.Required(o, Inbox::VT_ITEMS);
    return o;
  }
};

inline ::flatbuffers::Offset<Inbox> CreateInbox(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<InboxItem>>> items = 0) {
  InboxBuilder builder_(_fbb);
  builder_.add_items(items);
  return builder_.Finish();
}

struct Inbox::Traits {
  using type = Inbox;
  static auto constexpr Create = CreateInbox;
};

inline ::flatbuffers::Offset<Inbox> CreateInboxDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<::flatbuffers::Offset<InboxItem>> *items = nullptr) {
  auto items__ = items ? _fbb.CreateVector<::flatbuffers::Offset<InboxItem>>(*items) : 0;
  return CreateInbox(
      _fbb,
      items__);
}

inline bool VerifyNotificationUnion(::flatbuffers::Verifier &verifier, const void *obj, NotificationUnion type) {
  switch (type) {
    case NotificationUnion::NONE: {
      return true;
    }
    case NotificationUnion::Share: {
      auto ptr = reinterpret_cast<const Share *>(obj);
      return verifier.VerifyTable(ptr);
    }
    case NotificationUnion::JobComplete: {
      auto ptr = reinterpret_cast<const JobComplete *>(obj);
      return verifier.VerifyTable(ptr);
    }
    case NotificationUnion::AccessRequest: {
      auto ptr = reinterpret_cast<const AccessRequest *>(obj);
      return verifier.VerifyTable(ptr);
    }
    case NotificationUnion::DriveChange: {
      auto ptr = reinterpret_cast<const DriveChange *>(obj);
      return verifier.VerifyTable(ptr);
    }
    default: return true;
  }
}

inline bool VerifyNotificationUnionVector(::flatbuffers::Verifier &verifier, const ::flatbuffers::Vector<::flatbuffers::Offset<void>> *values, const ::flatbuffers::Vector<NotificationUnion> *types) {
  if (!values || !types) return !values && !types;
  if (values->size() != types->size()) return false;
  for (::flatbuffers::uoffset_t i = 0; i < values->size(); ++i) {
    if (!VerifyNotificationUnion(
        verifier,  values->Get(i), types->GetEnum<NotificationUnion>(i))) {
      return false;
    }
  }
  return true;
}

#endif  // FLATBUFFERS_GENERATED_NOTIFICATION_H_
