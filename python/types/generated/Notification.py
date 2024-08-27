# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .B2cId import B2cId
from flatbuffers.table import Table
from typing import Optional
np = import_numpy()

class Notification(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Notification()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsNotification(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Notification
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Notification
    def Sender(self) -> Optional[B2cId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = B2cId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Notification
    def NotificationType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, o + self._tab.Pos)
        return 0

    # Notification
    def Notification(self) -> Optional[flatbuffers.table.Table]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            obj = Table(bytearray(), 0)
            self._tab.Union(obj, o)
            return obj
        return None

def NotificationStart(builder: flatbuffers.Builder):
    builder.StartObject(3)

def Start(builder: flatbuffers.Builder):
    NotificationStart(builder)

def NotificationAddSender(builder: flatbuffers.Builder, sender: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(sender), 0)

def AddSender(builder: flatbuffers.Builder, sender: int):
    NotificationAddSender(builder, sender)

def NotificationAddNotificationType(builder: flatbuffers.Builder, notificationType: int):
    builder.PrependUint8Slot(1, notificationType, 0)

def AddNotificationType(builder: flatbuffers.Builder, notificationType: int):
    NotificationAddNotificationType(builder, notificationType)

def NotificationAddNotification(builder: flatbuffers.Builder, notification: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(notification), 0)

def AddNotification(builder: flatbuffers.Builder, notification: int):
    NotificationAddNotification(builder, notification)

def NotificationEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return NotificationEnd(builder)
