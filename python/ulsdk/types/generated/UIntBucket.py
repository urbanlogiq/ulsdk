# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
np = import_numpy()

class UIntBucket(object):
    __slots__ = ['_tab']

    @classmethod
    def SizeOf(cls) -> int:
        return 16

    # UIntBucket
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # UIntBucket
    def Count(self): return self._tab.Get(flatbuffers.number_types.Uint64Flags, self._tab.Pos + flatbuffers.number_types.UOffsetTFlags.py_type(0))
    # UIntBucket
    def Max(self): return self._tab.Get(flatbuffers.number_types.Uint64Flags, self._tab.Pos + flatbuffers.number_types.UOffsetTFlags.py_type(8))

def CreateUIntBucket(builder, count, max):
    builder.Prep(8, 16)
    builder.PrependUint64(max)
    builder.PrependUint64(count)
    return builder.Offset()
