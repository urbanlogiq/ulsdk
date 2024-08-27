# automatically generated by the FlatBuffers compiler, do not modify

# namespace: reflection

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .EnumVal import EnumVal
from .KeyValue import KeyValue
from .Type import Type
from typing import Optional
np = import_numpy()

class Enum(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Enum()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsEnum(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    @classmethod
    def EnumBufferHasIdentifier(cls, buf, offset, size_prefixed=False):
        return flatbuffers.util.BufferHasIdentifier(buf, offset, b"\x42\x46\x42\x53", size_prefixed=size_prefixed)

    # Enum
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Enum
    def Name(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Enum
    def Values(self, j: int) -> Optional[EnumVal]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = EnumVal()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Enum
    def ValuesLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Enum
    def ValuesIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        return o == 0

    # Enum
    def IsUnion(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return bool(self._tab.Get(flatbuffers.number_types.BoolFlags, o + self._tab.Pos))
        return False

    # Enum
    def UnderlyingType(self) -> Optional[Type]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = Type()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Enum
    def Attributes(self, j: int) -> Optional[KeyValue]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = KeyValue()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Enum
    def AttributesLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Enum
    def AttributesIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        return o == 0

    # Enum
    def Documentation(self, j: int):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.String(a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 4))
        return ""

    # Enum
    def DocumentationLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Enum
    def DocumentationIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        return o == 0

    # File that this Enum is declared in.
    # Enum
    def DeclarationFile(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(16))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

def EnumStart(builder: flatbuffers.Builder):
    builder.StartObject(7)

def Start(builder: flatbuffers.Builder):
    EnumStart(builder)

def EnumAddName(builder: flatbuffers.Builder, name: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(name), 0)

def AddName(builder: flatbuffers.Builder, name: int):
    EnumAddName(builder, name)

def EnumAddValues(builder: flatbuffers.Builder, values: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(values), 0)

def AddValues(builder: flatbuffers.Builder, values: int):
    EnumAddValues(builder, values)

def EnumStartValuesVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartValuesVector(builder, numElems: int) -> int:
    return EnumStartValuesVector(builder, numElems)

def EnumAddIsUnion(builder: flatbuffers.Builder, isUnion: bool):
    builder.PrependBoolSlot(2, isUnion, 0)

def AddIsUnion(builder: flatbuffers.Builder, isUnion: bool):
    EnumAddIsUnion(builder, isUnion)

def EnumAddUnderlyingType(builder: flatbuffers.Builder, underlyingType: int):
    builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(underlyingType), 0)

def AddUnderlyingType(builder: flatbuffers.Builder, underlyingType: int):
    EnumAddUnderlyingType(builder, underlyingType)

def EnumAddAttributes(builder: flatbuffers.Builder, attributes: int):
    builder.PrependUOffsetTRelativeSlot(4, flatbuffers.number_types.UOffsetTFlags.py_type(attributes), 0)

def AddAttributes(builder: flatbuffers.Builder, attributes: int):
    EnumAddAttributes(builder, attributes)

def EnumStartAttributesVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartAttributesVector(builder, numElems: int) -> int:
    return EnumStartAttributesVector(builder, numElems)

def EnumAddDocumentation(builder: flatbuffers.Builder, documentation: int):
    builder.PrependUOffsetTRelativeSlot(5, flatbuffers.number_types.UOffsetTFlags.py_type(documentation), 0)

def AddDocumentation(builder: flatbuffers.Builder, documentation: int):
    EnumAddDocumentation(builder, documentation)

def EnumStartDocumentationVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartDocumentationVector(builder, numElems: int) -> int:
    return EnumStartDocumentationVector(builder, numElems)

def EnumAddDeclarationFile(builder: flatbuffers.Builder, declarationFile: int):
    builder.PrependUOffsetTRelativeSlot(6, flatbuffers.number_types.UOffsetTFlags.py_type(declarationFile), 0)

def AddDeclarationFile(builder: flatbuffers.Builder, declarationFile: int):
    EnumAddDeclarationFile(builder, declarationFile)

def EnumEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return EnumEnd(builder)
