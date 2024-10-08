# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class Layout(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Layout()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsLayout(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Layout
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # The height of the chart tile in react-grid-layout grid units
    # Layout
    def Height(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # The width in react-grid-layout grid units
    # Layout
    def Width(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # The x position in react-grid-layout grid units
    # Layout
    def X(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

    # The y position in react-grid-layout grid units
    # Layout
    def Y(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint32Flags, o + self._tab.Pos)
        return 0

def LayoutStart(builder: flatbuffers.Builder):
    builder.StartObject(4)

def Start(builder: flatbuffers.Builder):
    LayoutStart(builder)

def LayoutAddHeight(builder: flatbuffers.Builder, height: int):
    builder.PrependUint32Slot(0, height, 0)

def AddHeight(builder: flatbuffers.Builder, height: int):
    LayoutAddHeight(builder, height)

def LayoutAddWidth(builder: flatbuffers.Builder, width: int):
    builder.PrependUint32Slot(1, width, 0)

def AddWidth(builder: flatbuffers.Builder, width: int):
    LayoutAddWidth(builder, width)

def LayoutAddX(builder: flatbuffers.Builder, x: int):
    builder.PrependUint32Slot(2, x, 0)

def AddX(builder: flatbuffers.Builder, x: int):
    LayoutAddX(builder, x)

def LayoutAddY(builder: flatbuffers.Builder, y: int):
    builder.PrependUint32Slot(3, y, 0)

def AddY(builder: flatbuffers.Builder, y: int):
    LayoutAddY(builder, y)

def LayoutEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return LayoutEnd(builder)
