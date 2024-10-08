# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .Attr import Attr
from .ContentId import ContentId
from .OpEntry import OpEntry
from typing import Optional
np = import_numpy()

# A DiffStream encodes a sequence of operations that should be performed on a table.
# The operations are applied in order to the table, i.e. the ordering of the `seq` field is significant.
class DiffStream(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = DiffStream()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsDiffStream(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # DiffStream
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # This is the head revision of the directory object that contains the table.
    # DiffStream
    def Base(self) -> Optional[ContentId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ContentId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # DiffStream
    def Seq(self, j: int) -> Optional[OpEntry]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = OpEntry()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # DiffStream
    def SeqLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # DiffStream
    def SeqIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        return o == 0

    # We can optionally associate attributes with the diffstream.
    # When the change history of the table is retrieved, the attributes from the diffstream
    # will be accessible as the `attributes` field on the ChangeSet associated with this diffstream.
    # DiffStream
    def Attributes(self, j: int) -> Optional[Attr]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = Attr()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # DiffStream
    def AttributesLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # DiffStream
    def AttributesIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        return o == 0

def DiffStreamStart(builder: flatbuffers.Builder):
    builder.StartObject(3)

def Start(builder: flatbuffers.Builder):
    DiffStreamStart(builder)

def DiffStreamAddBase(builder: flatbuffers.Builder, base: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(base), 0)

def AddBase(builder: flatbuffers.Builder, base: int):
    DiffStreamAddBase(builder, base)

def DiffStreamAddSeq(builder: flatbuffers.Builder, seq: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(seq), 0)

def AddSeq(builder: flatbuffers.Builder, seq: int):
    DiffStreamAddSeq(builder, seq)

def DiffStreamStartSeqVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartSeqVector(builder, numElems: int) -> int:
    return DiffStreamStartSeqVector(builder, numElems)

def DiffStreamAddAttributes(builder: flatbuffers.Builder, attributes: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(attributes), 0)

def AddAttributes(builder: flatbuffers.Builder, attributes: int):
    DiffStreamAddAttributes(builder, attributes)

def DiffStreamStartAttributesVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartAttributesVector(builder, numElems: int) -> int:
    return DiffStreamStartAttributesVector(builder, numElems)

def DiffStreamEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return DiffStreamEnd(builder)
