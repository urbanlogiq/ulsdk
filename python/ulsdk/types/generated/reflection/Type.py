# automatically generated by the FlatBuffers compiler, do not modify

# namespace: reflection

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class Type(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Type()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsType(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    @classmethod
    def TypeBufferHasIdentifier(cls, buf, offset, size_prefixed=False):
        return flatbuffers.util.BufferHasIdentifier(buf, offset, b"\x42\x46\x42\x53", size_prefixed=size_prefixed)

    # Type
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Type
    def BaseType(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int8Flags, o + self._tab.Pos)
        return 0

    # Type
    def Element(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int8Flags, o + self._tab.Pos)
        return 0

    # Type
    def Index(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return -1

    # Type
    def FixedLength(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint16Flags, o + self._tab.Pos)
        return 0

    # The size (octets) of the `base_type` field.
    # Type
    def BaseSize(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 4

    # The size (octets) of the `element` field, if present.
    # Type
    def ElementSize(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

def TypeStart(builder: flatbuffers.Builder):
    builder.StartObject(6)

def Start(builder: flatbuffers.Builder):
    TypeStart(builder)

def TypeAddBaseType(builder: flatbuffers.Builder, baseType: int):
    builder.PrependInt8Slot(0, baseType, 0)

def AddBaseType(builder: flatbuffers.Builder, baseType: int):
    TypeAddBaseType(builder, baseType)

def TypeAddElement(builder: flatbuffers.Builder, element: int):
    builder.PrependInt8Slot(1, element, 0)

def AddElement(builder: flatbuffers.Builder, element: int):
    TypeAddElement(builder, element)

def TypeAddIndex(builder: flatbuffers.Builder, index: int):
    builder.PrependInt32Slot(2, index, -1)

def AddIndex(builder: flatbuffers.Builder, index: int):
    TypeAddIndex(builder, index)

def TypeAddFixedLength(builder: flatbuffers.Builder, fixedLength: int):
    builder.PrependUint16Slot(3, fixedLength, 0)

def AddFixedLength(builder: flatbuffers.Builder, fixedLength: int):
    TypeAddFixedLength(builder, fixedLength)

def TypeAddBaseSize(builder: flatbuffers.Builder, baseSize: int):
    builder.PrependUint32Slot(4, baseSize, 4)

def AddBaseSize(builder: flatbuffers.Builder, baseSize: int):
    TypeAddBaseSize(builder, baseSize)

def TypeAddElementSize(builder: flatbuffers.Builder, elementSize: int):
    builder.PrependUint32Slot(5, elementSize, 0)

def AddElementSize(builder: flatbuffers.Builder, elementSize: int):
    TypeAddElementSize(builder, elementSize)

def TypeEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return TypeEnd(builder)
