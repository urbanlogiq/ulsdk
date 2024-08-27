# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from typing import Optional
np = import_numpy()

class Document(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Document()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsDocument(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Document
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Document
    def Filename(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Document
    def Url(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Document
    def MimeType(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Document
    def DisplayName(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

def DocumentStart(builder: flatbuffers.Builder):
    builder.StartObject(4)

def Start(builder: flatbuffers.Builder):
    DocumentStart(builder)

def DocumentAddFilename(builder: flatbuffers.Builder, filename: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(filename), 0)

def AddFilename(builder: flatbuffers.Builder, filename: int):
    DocumentAddFilename(builder, filename)

def DocumentAddUrl(builder: flatbuffers.Builder, url: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(url), 0)

def AddUrl(builder: flatbuffers.Builder, url: int):
    DocumentAddUrl(builder, url)

def DocumentAddMimeType(builder: flatbuffers.Builder, mimeType: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(mimeType), 0)

def AddMimeType(builder: flatbuffers.Builder, mimeType: int):
    DocumentAddMimeType(builder, mimeType)

def DocumentAddDisplayName(builder: flatbuffers.Builder, displayName: int):
    builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(displayName), 0)

def AddDisplayName(builder: flatbuffers.Builder, displayName: int):
    DocumentAddDisplayName(builder, displayName)

def DocumentEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return DocumentEnd(builder)