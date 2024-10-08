# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from dataclasses import dataclass
from enum import Enum
from flatbuffers.table import Table
from flatbuffers.builder import Builder
from flatbuffers.util import RemoveSizePrefix
from typing import Union, List, Optional, Self, Tuple
from .id import (
    B2cId,
    ColumnGroupId,
    ContentId,
    DataStateId,
    GenericId,
    GraphNodeId,
    ObjectId,
    ObjectNamespace,
    StreamId,
)
from .permissions import (
    AccessControlList,
    PermissionTy,
    Role,
)
from .generated.AccessControlList import AccessControlList as FbsAccessControlList
from .generated.AccessRequest import AccessRequest as FbsAccessRequest
from .generated.B2cId import B2cId as FbsB2cId
from .generated.ColumnGroupId import ColumnGroupId as FbsColumnGroupId
from .generated.ContentId import ContentId as FbsContentId
from .generated.DataStateId import DataStateId as FbsDataStateId
from .generated.DriveChange import DriveChange as FbsDriveChange
from .generated.GenericId import GenericId as FbsGenericId
from .generated.GraphNodeId import GraphNodeId as FbsGraphNodeId
from .generated.Inbox import Inbox as FbsInbox
from .generated.InboxItem import InboxItem as FbsInboxItem
from .generated.JobComplete import JobComplete as FbsJobComplete
from .generated.Notification import Notification as FbsNotification
from .generated.ObjectId import ObjectId as FbsObjectId
from .generated.Response import Response as FbsResponse
from .generated.Role import Role as FbsRole
from .generated.Share import Share as FbsShare
from .generated.ShareDetails import ShareDetails as FbsShareDetails
from .generated.StreamId import StreamId as FbsStreamId
from .generated.NotificationUnion import NotificationUnion as FbsNotificationUnion

class DriveAction(Enum):
    Add = 0
    Remove = 1
    Overwrite = 2

class ReadStatus(Enum):
    Unread = 0
    Read = 1

class RequestStatus(Enum):
    Pending = 0
    Approved = 1
    Rejected = 2


@dataclass
class Share:
    dest: Optional["str"]

    msg: Optional["str"]

    new_perms: "PermissionTy"

    object: "ObjectId"

    old_perms: "PermissionTy"

    @classmethod
    def from_fbs(cls, o: FbsShare) -> Self:
        dest = None
        dest_str = o.Dest()
        if dest_str is not None:
            dest = dest_str.decode('utf-8')
        msg = None
        msg_str = o.Msg()
        if msg_str is not None:
            msg = msg_str.decode('utf-8')
        new_perms = PermissionTy(o.NewPerms())
        object_obj = o.Object()
        if object_obj is not None:
            object = ObjectId.from_fbs(object_obj)
        else:
            raise ValueError("Object is required")
        old_perms = PermissionTy(o.OldPerms())
        return cls(dest, msg, new_perms, object, old_perms)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsShare.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Share import (
            Start,
            AddDest,
            AddMsg,
            AddNewPerms,
            AddObject,
            AddOldPerms,
            End,
        )
        dest_offset = None
        if self.dest is not None:
            dest_offset = builder.CreateString(self.dest)
        msg_offset = None
        if self.msg is not None:
            msg_offset = builder.CreateString(self.msg)
        object_offset = self.object.serialize_to(builder)
        
        Start(builder)
        if dest_offset is not None:
            AddDest(builder, dest_offset)
        if msg_offset is not None:
            AddMsg(builder, msg_offset)
        AddNewPerms(builder, self.new_perms.value)
        AddObject(builder, object_offset)
        AddOldPerms(builder, self.old_perms.value)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        dest = ""
        msg = ""
        new_perms = PermissionTy(1)
        object = ObjectId.make_default()
        old_perms = PermissionTy(1)
        return cls(dest, msg, new_perms, object, old_perms)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.dest == other.dest
        eq = eq and self.msg == other.msg
        eq = eq and self.new_perms == other.new_perms
        eq = eq and self.object == other.object
        eq = eq and self.old_perms == other.old_perms

        return eq

@dataclass
class JobComplete:
    job: "ObjectId"

    @classmethod
    def from_fbs(cls, o: FbsJobComplete) -> Self:
        job_obj = o.Job()
        if job_obj is not None:
            job = ObjectId.from_fbs(job_obj)
        else:
            raise ValueError("Job is required")
        return cls(job)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsJobComplete.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.JobComplete import (
            Start,
            AddJob,
            End,
        )
        job_offset = self.job.serialize_to(builder)
        
        Start(builder)
        AddJob(builder, job_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        job = ObjectId.make_default()
        return cls(job)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.job == other.job

        return eq

@dataclass
class AccessRequest:
    msg: Optional["str"]

    object: "ObjectId"

    perms: "int"

    requested_ownership: "int"

    status: "RequestStatus"

    @classmethod
    def from_fbs(cls, o: FbsAccessRequest) -> Self:
        msg = None
        msg_str = o.Msg()
        if msg_str is not None:
            msg = msg_str.decode('utf-8')
        object_obj = o.Object()
        if object_obj is not None:
            object = ObjectId.from_fbs(object_obj)
        else:
            raise ValueError("Object is required")
        perms = o.Perms()
        requested_ownership = o.RequestedOwnership()
        status = RequestStatus(o.Status())
        return cls(msg, object, perms, requested_ownership, status)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsAccessRequest.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.AccessRequest import (
            Start,
            AddMsg,
            AddObject,
            AddPerms,
            AddRequestedOwnership,
            AddStatus,
            End,
        )
        msg_offset = None
        if self.msg is not None:
            msg_offset = builder.CreateString(self.msg)
        object_offset = self.object.serialize_to(builder)
        
        Start(builder)
        if msg_offset is not None:
            AddMsg(builder, msg_offset)
        AddObject(builder, object_offset)
        AddPerms(builder, self.perms)
        AddRequestedOwnership(builder, self.requested_ownership)
        AddStatus(builder, self.status.value)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        msg = ""
        object = ObjectId.make_default()
        perms = 0
        requested_ownership = 0
        status = RequestStatus(0)
        return cls(msg, object, perms, requested_ownership, status)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.msg == other.msg
        eq = eq and self.object == other.object
        eq = eq and self.perms == other.perms
        eq = eq and self.requested_ownership == other.requested_ownership
        eq = eq and self.status == other.status

        return eq

@dataclass
class DriveChange:
    action: "DriveAction"

    object: "ObjectId"

    root: "ObjectId"

    @classmethod
    def from_fbs(cls, o: FbsDriveChange) -> Self:
        action = DriveAction(o.Action())
        object_obj = o.Object()
        if object_obj is not None:
            object = ObjectId.from_fbs(object_obj)
        else:
            raise ValueError("Object is required")
        root_obj = o.Root()
        if root_obj is not None:
            root = ObjectId.from_fbs(root_obj)
        else:
            raise ValueError("Root is required")
        return cls(action, object, root)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsDriveChange.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.DriveChange import (
            Start,
            AddAction,
            AddObject,
            AddRoot,
            End,
        )
        object_offset = self.object.serialize_to(builder)
        root_offset = self.root.serialize_to(builder)
        
        Start(builder)
        AddAction(builder, self.action.value)
        AddObject(builder, object_offset)
        AddRoot(builder, root_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        action = DriveAction(0)
        object = ObjectId.make_default()
        root = ObjectId.make_default()
        return cls(action, object, root)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.action == other.action
        eq = eq and self.object == other.object
        eq = eq and self.root == other.root

        return eq

@dataclass
class NotificationUnion:
    value: Union[
        "Share",
        "JobComplete",
        "AccessRequest",
        "DriveChange",
    ]

    def serialize_to(self, builder: Builder) -> Tuple[int, int]:
        from .generated.NotificationUnion import NotificationUnion
        offset = self.value.serialize_to(builder)
        if isinstance(self.value, Share):
            return (offset, NotificationUnion().Share)
        elif isinstance(self.value, JobComplete):
            return (offset, NotificationUnion().JobComplete)
        elif isinstance(self.value, AccessRequest):
            return (offset, NotificationUnion().AccessRequest)
        elif isinstance(self.value, DriveChange):
            return (offset, NotificationUnion().DriveChange)
        raise ValueError("Invalid union type")

    @classmethod
    def from_fbs(cls, o: Optional[Table], ty: int) -> Self:
        assert o is not None
        source = o.Bytes
        pos = o.Pos
        NotificationUnion_ty_instance = FbsNotificationUnion()
        if ty == NotificationUnion_ty_instance.Share:
            val = FbsShare();
            val.Init(source, pos)
            return cls(Share.from_fbs(val))
        elif ty == NotificationUnion_ty_instance.JobComplete:
            val = FbsJobComplete();
            val.Init(source, pos)
            return cls(JobComplete.from_fbs(val))
        elif ty == NotificationUnion_ty_instance.AccessRequest:
            val = FbsAccessRequest();
            val.Init(source, pos)
            return cls(AccessRequest.from_fbs(val))
        elif ty == NotificationUnion_ty_instance.DriveChange:
            val = FbsDriveChange();
            val.Init(source, pos)
            return cls(DriveChange.from_fbs(val))
        else:
            raise ValueError("Invalid union type")

    @classmethod
    def make_default(cls) -> Self:
        return cls(Share.make_default())

    def __eq__(self, other) -> bool:
        if type(self.value) is not type(other.value):
            return False
        return self.value == other.value

@dataclass
class Inbox:
    items: "List[InboxItem]"

    @classmethod
    def from_fbs(cls, o: FbsInbox) -> Self:
        items = list()
        if not o.ItemsIsNone():
            for i in range(o.ItemsLength()):
                items_val = None
                items_obj = o.Items(i)
                if items_obj is not None:
                    items_val = InboxItem.from_fbs(items_obj)
                items.append(items_val)
        return cls(items)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsInbox.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Inbox import (
            Start,
            AddItems,
            StartItemsVector,
            End,
        )
        items_offsets = list()
        for value in self.items:
            items_offsets.append(value.serialize_to(builder))
        StartItemsVector(builder, len(self.items))
        for i in reversed(range(len(self.items))):
            builder.PrependUOffsetTRelative(items_offsets[i])
        items_offset = builder.EndVector()
        
        Start(builder)
        AddItems(builder, items_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        items = []
        return cls(items)

    def __eq__(self, other) -> bool:
        eq = True
        if len(self.items) != len(other.items):
            return False
        for i in range(len(self.items)):
            eq = eq and self.items[i] == other.items[i]

        return eq

@dataclass
class InboxItem:
    notification: "ObjectId"

    status: "ReadStatus"

    time: "int"

    @classmethod
    def from_fbs(cls, o: FbsInboxItem) -> Self:
        notification_obj = o.Notification()
        if notification_obj is not None:
            notification = ObjectId.from_fbs(notification_obj)
        else:
            raise ValueError("Notification is required")
        status = ReadStatus(o.Status())
        time = o.Time()
        return cls(notification, status, time)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsInboxItem.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.InboxItem import (
            Start,
            AddNotification,
            AddStatus,
            AddTime,
            End,
        )
        notification_offset = self.notification.serialize_to(builder)
        
        Start(builder)
        AddNotification(builder, notification_offset)
        AddStatus(builder, self.status.value)
        AddTime(builder, self.time)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        notification = ObjectId.make_default()
        status = ReadStatus(0)
        time = 0
        return cls(notification, status, time)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.notification == other.notification
        eq = eq and self.status == other.status
        eq = eq and self.time == other.time

        return eq

@dataclass
class Notification:
    notification: Optional["NotificationUnion"]

    sender: Optional["B2cId"]

    @classmethod
    def from_fbs(cls, o: FbsNotification) -> Self:
        notification = None
        notification_val = o.Notification()
        if notification_val is not None:
            notification_ty = o.NotificationType()
            notification = NotificationUnion.from_fbs(notification_val, notification_ty)
        sender = None
        sender_obj = o.Sender()
        if sender_obj is not None:
            sender = B2cId.from_fbs(sender_obj)
        return cls(notification, sender)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsNotification.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Notification import (
            Start,
            AddNotification,
            AddNotificationType,
            AddSender,
            End,
        )
        notification_offset, notification_ty = (None, None)
        if self.notification is not None:
            notification_offset, notification_ty = self.notification.serialize_to(builder)
        sender_offset = None
        if self.sender is not None:
            sender_offset = self.sender.serialize_to(builder)
        
        Start(builder)
        if notification_offset is not None and notification_ty is not None:
            AddNotification(builder, notification_offset)
            AddNotificationType(builder, notification_ty)
        if sender_offset is not None:
            AddSender(builder, sender_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        notification = NotificationUnion.make_default()
        sender = B2cId.make_default()
        return cls(notification, sender)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.notification == other.notification
        eq = eq and self.sender == other.sender

        return eq

@dataclass
class Response:
    msg: Optional["str"]

    @classmethod
    def from_fbs(cls, o: FbsResponse) -> Self:
        msg = None
        msg_str = o.Msg()
        if msg_str is not None:
            msg = msg_str.decode('utf-8')
        return cls(msg)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsResponse.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Response import (
            Start,
            AddMsg,
            End,
        )
        msg_offset = None
        if self.msg is not None:
            msg_offset = builder.CreateString(self.msg)
        
        Start(builder)
        if msg_offset is not None:
            AddMsg(builder, msg_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        msg = ""
        return cls(msg)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.msg == other.msg

        return eq

@dataclass
class ShareDetails:
    msg: Optional["str"]

    notify: "bool"

    @classmethod
    def from_fbs(cls, o: FbsShareDetails) -> Self:
        msg = None
        msg_str = o.Msg()
        if msg_str is not None:
            msg = msg_str.decode('utf-8')
        notify = o.Notify()
        return cls(msg, notify)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsShareDetails.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.ShareDetails import (
            Start,
            AddMsg,
            AddNotify,
            End,
        )
        msg_offset = None
        if self.msg is not None:
            msg_offset = builder.CreateString(self.msg)
        
        Start(builder)
        if msg_offset is not None:
            AddMsg(builder, msg_offset)
        AddNotify(builder, self.notify)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        msg = ""
        notify = False
        return cls(msg, notify)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.msg == other.msg
        eq = eq and self.notify == other.notify

        return eq
