# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class CategoryRelationshipData(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = CategoryRelationshipData()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsCategoryRelationshipData(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # CategoryRelationshipData
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # CategoryRelationshipData
    def Categories(self, j: int):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Int32Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 4))
        return 0

    # CategoryRelationshipData
    def CategoriesAsNumpy(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Int32Flags, o)
        return 0

    # CategoryRelationshipData
    def CategoriesLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # CategoryRelationshipData
    def CategoriesIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        return o == 0

    # CategoryRelationshipData
    def AssociatedFields(self, j: int):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Int32Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 4))
        return 0

    # CategoryRelationshipData
    def AssociatedFieldsAsNumpy(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Int32Flags, o)
        return 0

    # CategoryRelationshipData
    def AssociatedFieldsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # CategoryRelationshipData
    def AssociatedFieldsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        return o == 0

def CategoryRelationshipDataStart(builder: flatbuffers.Builder):
    builder.StartObject(2)

def Start(builder: flatbuffers.Builder):
    CategoryRelationshipDataStart(builder)

def CategoryRelationshipDataAddCategories(builder: flatbuffers.Builder, categories: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(categories), 0)

def AddCategories(builder: flatbuffers.Builder, categories: int):
    CategoryRelationshipDataAddCategories(builder, categories)

def CategoryRelationshipDataStartCategoriesVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartCategoriesVector(builder, numElems: int) -> int:
    return CategoryRelationshipDataStartCategoriesVector(builder, numElems)

def CategoryRelationshipDataAddAssociatedFields(builder: flatbuffers.Builder, associatedFields: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(associatedFields), 0)

def AddAssociatedFields(builder: flatbuffers.Builder, associatedFields: int):
    CategoryRelationshipDataAddAssociatedFields(builder, associatedFields)

def CategoryRelationshipDataStartAssociatedFieldsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartAssociatedFieldsVector(builder, numElems: int) -> int:
    return CategoryRelationshipDataStartAssociatedFieldsVector(builder, numElems)

def CategoryRelationshipDataEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return CategoryRelationshipDataEnd(builder)