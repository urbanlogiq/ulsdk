# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .ObjectId import ObjectId
from .Task import Task
from .TaskParameter import TaskParameter
from typing import Optional
np = import_numpy()

class Job(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Job()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsJob(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Job
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Is the job complete?
    # Job
    def Status(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int8Flags, o + self._tab.Pos)
        return 0

    # User ID who created this job.
    # Job
    def UserId(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # A list of all the tasks that constitute this job.
    # Job
    def Tasks(self, j: int) -> Optional[Task]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = Task()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Job
    def TasksLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Job
    def TasksIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        return o == 0

    # Parameters verbatim from the RunSpec
    # Job
    def Params(self, j: int) -> Optional[TaskParameter]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = TaskParameter()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Job
    def ParamsLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Job
    def ParamsIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        return o == 0

    # Job
    def ErrorTys(self, j: int):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Int32Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 4))
        return 0

    # Job
    def ErrorTysAsNumpy(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Int32Flags, o)
        return 0

    # Job
    def ErrorTysLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Job
    def ErrorTysIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        return o == 0

def JobStart(builder: flatbuffers.Builder):
    builder.StartObject(5)

def Start(builder: flatbuffers.Builder):
    JobStart(builder)

def JobAddStatus(builder: flatbuffers.Builder, status: int):
    builder.PrependInt8Slot(0, status, 0)

def AddStatus(builder: flatbuffers.Builder, status: int):
    JobAddStatus(builder, status)

def JobAddUserId(builder: flatbuffers.Builder, userId: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(userId), 0)

def AddUserId(builder: flatbuffers.Builder, userId: int):
    JobAddUserId(builder, userId)

def JobAddTasks(builder: flatbuffers.Builder, tasks: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(tasks), 0)

def AddTasks(builder: flatbuffers.Builder, tasks: int):
    JobAddTasks(builder, tasks)

def JobStartTasksVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartTasksVector(builder, numElems: int) -> int:
    return JobStartTasksVector(builder, numElems)

def JobAddParams(builder: flatbuffers.Builder, params: int):
    builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(params), 0)

def AddParams(builder: flatbuffers.Builder, params: int):
    JobAddParams(builder, params)

def JobStartParamsVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartParamsVector(builder, numElems: int) -> int:
    return JobStartParamsVector(builder, numElems)

def JobAddErrorTys(builder: flatbuffers.Builder, errorTys: int):
    builder.PrependUOffsetTRelativeSlot(4, flatbuffers.number_types.UOffsetTFlags.py_type(errorTys), 0)

def AddErrorTys(builder: flatbuffers.Builder, errorTys: int):
    JobAddErrorTys(builder, errorTys)

def JobStartErrorTysVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartErrorTysVector(builder, numElems: int) -> int:
    return JobStartErrorTysVector(builder, numElems)

def JobEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return JobEnd(builder)
