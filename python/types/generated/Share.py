# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .ObjectId import ObjectId
from typing import Optional
np = import_numpy()

class Share(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Share()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsShare(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Share
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Share
    def Object(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Share
    def Dest(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Share
    def Msg(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Share
    def OldPerms(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # Share
    def NewPerms(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

def ShareStart(builder: flatbuffers.Builder):
    builder.StartObject(5)

def Start(builder: flatbuffers.Builder):
    ShareStart(builder)

def ShareAddObject(builder: flatbuffers.Builder, object: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(object), 0)

def AddObject(builder: flatbuffers.Builder, object: int):
    ShareAddObject(builder, object)

def ShareAddDest(builder: flatbuffers.Builder, dest: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(dest), 0)

def AddDest(builder: flatbuffers.Builder, dest: int):
    ShareAddDest(builder, dest)

def ShareAddMsg(builder: flatbuffers.Builder, msg: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(msg), 0)

def AddMsg(builder: flatbuffers.Builder, msg: int):
    ShareAddMsg(builder, msg)

def ShareAddOldPerms(builder: flatbuffers.Builder, oldPerms: int):
    builder.PrependUint32Slot(3, oldPerms, 0)

def AddOldPerms(builder: flatbuffers.Builder, oldPerms: int):
    ShareAddOldPerms(builder, oldPerms)

def ShareAddNewPerms(builder: flatbuffers.Builder, newPerms: int):
    builder.PrependUint32Slot(4, newPerms, 0)

def AddNewPerms(builder: flatbuffers.Builder, newPerms: int):
    ShareAddNewPerms(builder, newPerms)

def ShareEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return ShareEnd(builder)