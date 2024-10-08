# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .Document import Document
from typing import Optional
np = import_numpy()

class Documents(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Documents()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsDocuments(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Documents
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Documents
    def Documents(self, j: int) -> Optional[Document]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = Document()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Documents
    def DocumentsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Documents
    def DocumentsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        return o == 0

def DocumentsStart(builder: flatbuffers.Builder):
    builder.StartObject(1)

def Start(builder: flatbuffers.Builder):
    DocumentsStart(builder)

def DocumentsAddDocuments(builder: flatbuffers.Builder, documents: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(documents), 0)

def AddDocuments(builder: flatbuffers.Builder, documents: int):
    DocumentsAddDocuments(builder, documents)

def DocumentsStartDocumentsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartDocumentsVector(builder, numElems: int) -> int:
    return DocumentsStartDocumentsVector(builder, numElems)

def DocumentsEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return DocumentsEnd(builder)
