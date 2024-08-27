# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .ObjectId import ObjectId
from .UserSettings import UserSettings
from .WorklogParameter import WorklogParameter
from typing import Optional
np = import_numpy()

class WorkLog(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = WorkLog()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsWorkLog(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # WorkLog
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # A human-readable tag.
    # WorkLog
    def Name(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Input streams and/or worklogs. These may be either work logs or streams.
    # WorkLog
    def InputStreams(self, j: int) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # WorkLog
    def InputStreamsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # WorkLog
    def InputStreamsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        return o == 0

    # The schematic used behind creating the worklog. This may be empty/null
    # if we are just layering data, for example.
    # WorkLog
    def Schematic(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # The output_streams contain a list of Parquet documents that consist of
    # the results. These documents may expire (ie: if this is a temporary
    # step) so there should be enough information in the worklog necessary
    # to reconstruct these output streams.
    # WorkLog
    def OutputStreams(self, j: int) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # WorkLog
    def OutputStreamsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # WorkLog
    def OutputStreamsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        return o == 0

    # These are the serialized parameters passed into the task which created
    # this worklog.
    # WorkLog
    def Params(self, j: int) -> Optional[WorklogParameter]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = WorklogParameter()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # WorkLog
    def ParamsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # WorkLog
    def ParamsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        return o == 0

    # Worklogs can contain multiple "levels". Consider the case where the user
    # submits a request for multiple ADT reports. We will create separate ADT
    # reports as required but also one that ties them all together. There are a
    # couple reasons for this; the primary is that the output of a schematic
    # node is allocated before the job is run and before it knows how many
    # worklogs will be generated. Another is that it makes it it easy (or
    # easier) to organize because we can sort based on "stuff the user requested",
    # instead of just "stuff the system generated".
    # WorkLog
    def Parent(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(16))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # WorkLog
    def UserSettings(self) -> Optional[UserSettings]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(18))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = UserSettings()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # WorkLog
    def JobId(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(20))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

def WorkLogStart(builder: flatbuffers.Builder):
    builder.StartObject(9)

def Start(builder: flatbuffers.Builder):
    WorkLogStart(builder)

def WorkLogAddName(builder: flatbuffers.Builder, name: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(name), 0)

def AddName(builder: flatbuffers.Builder, name: int):
    WorkLogAddName(builder, name)

def WorkLogAddInputStreams(builder: flatbuffers.Builder, inputStreams: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(inputStreams), 0)

def AddInputStreams(builder: flatbuffers.Builder, inputStreams: int):
    WorkLogAddInputStreams(builder, inputStreams)

def WorkLogStartInputStreamsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartInputStreamsVector(builder, numElems: int) -> int:
    return WorkLogStartInputStreamsVector(builder, numElems)

def WorkLogAddSchematic(builder: flatbuffers.Builder, schematic: int):
    builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(schematic), 0)

def AddSchematic(builder: flatbuffers.Builder, schematic: int):
    WorkLogAddSchematic(builder, schematic)

def WorkLogAddOutputStreams(builder: flatbuffers.Builder, outputStreams: int):
    builder.PrependUOffsetTRelativeSlot(4, flatbuffers.number_types.UOffsetTFlags.py_type(outputStreams), 0)

def AddOutputStreams(builder: flatbuffers.Builder, outputStreams: int):
    WorkLogAddOutputStreams(builder, outputStreams)

def WorkLogStartOutputStreamsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartOutputStreamsVector(builder, numElems: int) -> int:
    return WorkLogStartOutputStreamsVector(builder, numElems)

def WorkLogAddParams(builder: flatbuffers.Builder, params: int):
    builder.PrependUOffsetTRelativeSlot(5, flatbuffers.number_types.UOffsetTFlags.py_type(params), 0)

def AddParams(builder: flatbuffers.Builder, params: int):
    WorkLogAddParams(builder, params)

def WorkLogStartParamsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartParamsVector(builder, numElems: int) -> int:
    return WorkLogStartParamsVector(builder, numElems)

def WorkLogAddParent(builder: flatbuffers.Builder, parent: int):
    builder.PrependUOffsetTRelativeSlot(6, flatbuffers.number_types.UOffsetTFlags.py_type(parent), 0)

def AddParent(builder: flatbuffers.Builder, parent: int):
    WorkLogAddParent(builder, parent)

def WorkLogAddUserSettings(builder: flatbuffers.Builder, userSettings: int):
    builder.PrependUOffsetTRelativeSlot(7, flatbuffers.number_types.UOffsetTFlags.py_type(userSettings), 0)

def AddUserSettings(builder: flatbuffers.Builder, userSettings: int):
    WorkLogAddUserSettings(builder, userSettings)

def WorkLogAddJobId(builder: flatbuffers.Builder, jobId: int):
    builder.PrependUOffsetTRelativeSlot(8, flatbuffers.number_types.UOffsetTFlags.py_type(jobId), 0)

def AddJobId(builder: flatbuffers.Builder, jobId: int):
    WorkLogAddJobId(builder, jobId)

def WorkLogEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return WorkLogEnd(builder)