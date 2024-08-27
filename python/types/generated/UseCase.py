# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .UseCaseInputPair import UseCaseInputPair
from typing import Optional
np = import_numpy()

class UseCase(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = UseCase()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsUseCase(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # UseCase
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # UseCase
    def Ty(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # UseCase
    def Module(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # UseCase
    def Inputs(self, j: int) -> Optional[UseCaseInputPair]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = UseCaseInputPair()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # UseCase
    def InputsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # UseCase
    def InputsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        return o == 0

    # UseCase
    def Name(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # UseCase
    def Description(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # UseCase
    def Subtitle(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # UseCase
    def Abbreviation(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(16))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # UseCase
    def ExtendedTitle(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(18))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # UseCase
    def ExtendedDescription(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(20))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

def UseCaseStart(builder: flatbuffers.Builder):
    builder.StartObject(9)

def Start(builder: flatbuffers.Builder):
    UseCaseStart(builder)

def UseCaseAddTy(builder: flatbuffers.Builder, ty: int):
    builder.PrependUint32Slot(0, ty, 0)

def AddTy(builder: flatbuffers.Builder, ty: int):
    UseCaseAddTy(builder, ty)

def UseCaseAddModule(builder: flatbuffers.Builder, module: int):
    builder.PrependUint32Slot(1, module, 0)

def AddModule(builder: flatbuffers.Builder, module: int):
    UseCaseAddModule(builder, module)

def UseCaseAddInputs(builder: flatbuffers.Builder, inputs: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(inputs), 0)

def AddInputs(builder: flatbuffers.Builder, inputs: int):
    UseCaseAddInputs(builder, inputs)

def UseCaseStartInputsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartInputsVector(builder, numElems: int) -> int:
    return UseCaseStartInputsVector(builder, numElems)

def UseCaseAddName(builder: flatbuffers.Builder, name: int):
    builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(name), 0)

def AddName(builder: flatbuffers.Builder, name: int):
    UseCaseAddName(builder, name)

def UseCaseAddDescription(builder: flatbuffers.Builder, description: int):
    builder.PrependUOffsetTRelativeSlot(4, flatbuffers.number_types.UOffsetTFlags.py_type(description), 0)

def AddDescription(builder: flatbuffers.Builder, description: int):
    UseCaseAddDescription(builder, description)

def UseCaseAddSubtitle(builder: flatbuffers.Builder, subtitle: int):
    builder.PrependUOffsetTRelativeSlot(5, flatbuffers.number_types.UOffsetTFlags.py_type(subtitle), 0)

def AddSubtitle(builder: flatbuffers.Builder, subtitle: int):
    UseCaseAddSubtitle(builder, subtitle)

def UseCaseAddAbbreviation(builder: flatbuffers.Builder, abbreviation: int):
    builder.PrependUOffsetTRelativeSlot(6, flatbuffers.number_types.UOffsetTFlags.py_type(abbreviation), 0)

def AddAbbreviation(builder: flatbuffers.Builder, abbreviation: int):
    UseCaseAddAbbreviation(builder, abbreviation)

def UseCaseAddExtendedTitle(builder: flatbuffers.Builder, extendedTitle: int):
    builder.PrependUOffsetTRelativeSlot(7, flatbuffers.number_types.UOffsetTFlags.py_type(extendedTitle), 0)

def AddExtendedTitle(builder: flatbuffers.Builder, extendedTitle: int):
    UseCaseAddExtendedTitle(builder, extendedTitle)

def UseCaseAddExtendedDescription(builder: flatbuffers.Builder, extendedDescription: int):
    builder.PrependUOffsetTRelativeSlot(8, flatbuffers.number_types.UOffsetTFlags.py_type(extendedDescription), 0)

def AddExtendedDescription(builder: flatbuffers.Builder, extendedDescription: int):
    UseCaseAddExtendedDescription(builder, extendedDescription)

def UseCaseEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return UseCaseEnd(builder)