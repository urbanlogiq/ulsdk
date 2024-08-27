# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .ObjectId import ObjectId
from flatbuffers.table import Table
from typing import Optional
np = import_numpy()

class DirectoryEntry(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = DirectoryEntry()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsDirectoryEntry(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # DirectoryEntry
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # DirectoryEntry
    def EntryType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, o + self._tab.Pos)
        return 0

    # DirectoryEntry
    def Entry(self) -> Optional[flatbuffers.table.Table]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            obj = Table(bytearray(), 0)
            self._tab.Union(obj, o)
            return obj
        return None

    # DirectoryEntry
    def Parent(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

def DirectoryEntryStart(builder: flatbuffers.Builder):
    builder.StartObject(3)

def Start(builder: flatbuffers.Builder):
    DirectoryEntryStart(builder)

def DirectoryEntryAddEntryType(builder: flatbuffers.Builder, entryType: int):
    builder.PrependUint8Slot(0, entryType, 0)

def AddEntryType(builder: flatbuffers.Builder, entryType: int):
    DirectoryEntryAddEntryType(builder, entryType)

def DirectoryEntryAddEntry(builder: flatbuffers.Builder, entry: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(entry), 0)

def AddEntry(builder: flatbuffers.Builder, entry: int):
    DirectoryEntryAddEntry(builder, entry)

def DirectoryEntryAddParent(builder: flatbuffers.Builder, parent: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(parent), 0)

def AddParent(builder: flatbuffers.Builder, parent: int):
    DirectoryEntryAddParent(builder, parent)

def DirectoryEntryEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return DirectoryEntryEnd(builder)