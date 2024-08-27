# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .ContentId import ContentId
from .ObjectId import ObjectId
from flatbuffers.table import Table
from typing import Optional
np = import_numpy()

class DataCatalog(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = DataCatalog()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsDataCatalog(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # DataCatalog
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # DataCatalog
    def Id(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # DataCatalog
    def SubcollectionType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, o + self._tab.Pos)
        return 0

    # DataCatalog
    def Subcollection(self) -> Optional[flatbuffers.table.Table]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            obj = Table(bytearray(), 0)
            self._tab.Union(obj, o)
            return obj
        return None

    # DataCatalog
    def Revision(self) -> Optional[ContentId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ContentId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

def DataCatalogStart(builder: flatbuffers.Builder):
    builder.StartObject(4)

def Start(builder: flatbuffers.Builder):
    DataCatalogStart(builder)

def DataCatalogAddId(builder: flatbuffers.Builder, id: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(id), 0)

def AddId(builder: flatbuffers.Builder, id: int):
    DataCatalogAddId(builder, id)

def DataCatalogAddSubcollectionType(builder: flatbuffers.Builder, subcollectionType: int):
    builder.PrependUint8Slot(1, subcollectionType, 0)

def AddSubcollectionType(builder: flatbuffers.Builder, subcollectionType: int):
    DataCatalogAddSubcollectionType(builder, subcollectionType)

def DataCatalogAddSubcollection(builder: flatbuffers.Builder, subcollection: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(subcollection), 0)

def AddSubcollection(builder: flatbuffers.Builder, subcollection: int):
    DataCatalogAddSubcollection(builder, subcollection)

def DataCatalogAddRevision(builder: flatbuffers.Builder, revision: int):
    builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(revision), 0)

def AddRevision(builder: flatbuffers.Builder, revision: int):
    DataCatalogAddRevision(builder, revision)

def DataCatalogEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return DataCatalogEnd(builder)