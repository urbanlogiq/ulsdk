# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
from typing import Any
from .ObjectId import ObjectId
from .ParamIndices import ParamIndices
from typing import Optional
np = import_numpy()

class Task(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset: int = 0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Task()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsTask(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # Task
    def Init(self, buf: bytes, pos: int):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Task
    def _Id(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # User who created the job. This is the same as the user_id field in the
    # job structure but duplicated for convenience when looking up task related
    # information.
    # Task
    def UserId(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Task object, either a source or a stream
    # Task
    def Task(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Task
    def Name(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Associated Job ID
    # Task
    def JobId(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Task status
    # Task
    def Status(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int8Flags, o + self._tab.Pos)
        return 0

    # For errors, generic information.
    # Task
    def Message(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(16))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Parameter indices taken from the RunSpec for this particular task step.
    # Task
    def Params(self) -> Optional[ParamIndices]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(18))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ParamIndices()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # The output of this step. If the task is computational (ie: not just a
    # data stream lookup) this is a blank object where the results will be
    # written. If it is a lookup of an existing stream, this will be populated
    # with the stream ID
    # Task
    def Output(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(20))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # If false, keep this object if it's a temporary/intermediate after job
    # creation. This must not be set if the output object above is a provided
    # stream.
    # Task
    def Discard(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(22))
        if o != 0:
            return bool(self._tab.Get(flatbuffers.number_types.BoolFlags, o + self._tab.Pos))
        return False

    # The upstream nodes that enabled this task
    # Task
    def Upstream(self, j: int) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(24))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Task
    def UpstreamLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(24))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Task
    def UpstreamIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(24))
        return o == 0

    # The downstream nodes to enable once this task is complete
    # Task
    def Downstream(self, j: int) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(26))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # Task
    def DownstreamLength(self) -> int:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(26))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # Task
    def DownstreamIsNone(self) -> bool:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(26))
        return o == 0

    # Task creation time, in ms-since-Unix-epoch UTC.
    # Task
    def Created(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(28))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint64Flags, o + self._tab.Pos)
        return 0

    # Task start time, in ms-since-Unix-epoch UTC.
    # Task
    def Start(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(30))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint64Flags, o + self._tab.Pos)
        return 0

    # Task last poll time, in ms-since-Unix-epoch UTC.
    # Task
    def LastUpdated(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(32))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint64Flags, o + self._tab.Pos)
        return 0

    # Task
    def End(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(34))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint64Flags, o + self._tab.Pos)
        return 0

    # Task
    def Retries(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(36))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return 0

    # Task
    def BarrierCount(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(38))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return 0

    # Task
    def LastUpdatedByPod(self) -> Optional[bytes]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(40))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Task
    def Flags(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(42))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return 0

    # Task
    def ErrorTy(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(44))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return 0

    # Task
    def SchematicId(self) -> Optional[ObjectId]:
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(46))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            obj = ObjectId()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

def TaskStart(builder: flatbuffers.Builder):
    builder.StartObject(22)

def Start(builder: flatbuffers.Builder):
    TaskStart(builder)

def TaskAdd_Id(builder: flatbuffers.Builder, _Id: int):
    builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(_Id), 0)

def Add_Id(builder: flatbuffers.Builder, _Id: int):
    TaskAdd_Id(builder, _Id)

def TaskAddUserId(builder: flatbuffers.Builder, userId: int):
    builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(userId), 0)

def AddUserId(builder: flatbuffers.Builder, userId: int):
    TaskAddUserId(builder, userId)

def TaskAddTask(builder: flatbuffers.Builder, task: int):
    builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(task), 0)

def AddTask(builder: flatbuffers.Builder, task: int):
    TaskAddTask(builder, task)

def TaskAddName(builder: flatbuffers.Builder, name: int):
    builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(name), 0)

def AddName(builder: flatbuffers.Builder, name: int):
    TaskAddName(builder, name)

def TaskAddJobId(builder: flatbuffers.Builder, jobId: int):
    builder.PrependUOffsetTRelativeSlot(4, flatbuffers.number_types.UOffsetTFlags.py_type(jobId), 0)

def AddJobId(builder: flatbuffers.Builder, jobId: int):
    TaskAddJobId(builder, jobId)

def TaskAddStatus(builder: flatbuffers.Builder, status: int):
    builder.PrependInt8Slot(5, status, 0)

def AddStatus(builder: flatbuffers.Builder, status: int):
    TaskAddStatus(builder, status)

def TaskAddMessage(builder: flatbuffers.Builder, message: int):
    builder.PrependUOffsetTRelativeSlot(6, flatbuffers.number_types.UOffsetTFlags.py_type(message), 0)

def AddMessage(builder: flatbuffers.Builder, message: int):
    TaskAddMessage(builder, message)

def TaskAddParams(builder: flatbuffers.Builder, params: int):
    builder.PrependUOffsetTRelativeSlot(7, flatbuffers.number_types.UOffsetTFlags.py_type(params), 0)

def AddParams(builder: flatbuffers.Builder, params: int):
    TaskAddParams(builder, params)

def TaskAddOutput(builder: flatbuffers.Builder, output: int):
    builder.PrependUOffsetTRelativeSlot(8, flatbuffers.number_types.UOffsetTFlags.py_type(output), 0)

def AddOutput(builder: flatbuffers.Builder, output: int):
    TaskAddOutput(builder, output)

def TaskAddDiscard(builder: flatbuffers.Builder, discard: bool):
    builder.PrependBoolSlot(9, discard, 0)

def AddDiscard(builder: flatbuffers.Builder, discard: bool):
    TaskAddDiscard(builder, discard)

def TaskAddUpstream(builder: flatbuffers.Builder, upstream: int):
    builder.PrependUOffsetTRelativeSlot(10, flatbuffers.number_types.UOffsetTFlags.py_type(upstream), 0)

def AddUpstream(builder: flatbuffers.Builder, upstream: int):
    TaskAddUpstream(builder, upstream)

def TaskStartUpstreamVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartUpstreamVector(builder, numElems: int) -> int:
    return TaskStartUpstreamVector(builder, numElems)

def TaskAddDownstream(builder: flatbuffers.Builder, downstream: int):
    builder.PrependUOffsetTRelativeSlot(11, flatbuffers.number_types.UOffsetTFlags.py_type(downstream), 0)

def AddDownstream(builder: flatbuffers.Builder, downstream: int):
    TaskAddDownstream(builder, downstream)

def TaskStartDownstreamVector(builder, numElems: int) -> int:
    return builder.StartVector(4, numElems, 4)

def StartDownstreamVector(builder, numElems: int) -> int:
    return TaskStartDownstreamVector(builder, numElems)

def TaskAddCreated(builder: flatbuffers.Builder, created: int):
    builder.PrependUint64Slot(12, created, 0)

def AddCreated(builder: flatbuffers.Builder, created: int):
    TaskAddCreated(builder, created)

def TaskAddStart(builder: flatbuffers.Builder, start: int):
    builder.PrependUint64Slot(13, start, 0)

def AddStart(builder: flatbuffers.Builder, start: int):
    TaskAddStart(builder, start)

def TaskAddLastUpdated(builder: flatbuffers.Builder, lastUpdated: int):
    builder.PrependUint64Slot(14, lastUpdated, 0)

def AddLastUpdated(builder: flatbuffers.Builder, lastUpdated: int):
    TaskAddLastUpdated(builder, lastUpdated)

def TaskAddEnd(builder: flatbuffers.Builder, end: int):
    builder.PrependUint64Slot(15, end, 0)

def AddEnd(builder: flatbuffers.Builder, end: int):
    TaskAddEnd(builder, end)

def TaskAddRetries(builder: flatbuffers.Builder, retries: int):
    builder.PrependInt32Slot(16, retries, 0)

def AddRetries(builder: flatbuffers.Builder, retries: int):
    TaskAddRetries(builder, retries)

def TaskAddBarrierCount(builder: flatbuffers.Builder, barrierCount: int):
    builder.PrependInt32Slot(17, barrierCount, 0)

def AddBarrierCount(builder: flatbuffers.Builder, barrierCount: int):
    TaskAddBarrierCount(builder, barrierCount)

def TaskAddLastUpdatedByPod(builder: flatbuffers.Builder, lastUpdatedByPod: int):
    builder.PrependUOffsetTRelativeSlot(18, flatbuffers.number_types.UOffsetTFlags.py_type(lastUpdatedByPod), 0)

def AddLastUpdatedByPod(builder: flatbuffers.Builder, lastUpdatedByPod: int):
    TaskAddLastUpdatedByPod(builder, lastUpdatedByPod)

def TaskAddFlags(builder: flatbuffers.Builder, flags: int):
    builder.PrependInt32Slot(19, flags, 0)

def AddFlags(builder: flatbuffers.Builder, flags: int):
    TaskAddFlags(builder, flags)

def TaskAddErrorTy(builder: flatbuffers.Builder, errorTy: int):
    builder.PrependInt32Slot(20, errorTy, 0)

def AddErrorTy(builder: flatbuffers.Builder, errorTy: int):
    TaskAddErrorTy(builder, errorTy)

def TaskAddSchematicId(builder: flatbuffers.Builder, schematicId: int):
    builder.PrependUOffsetTRelativeSlot(21, flatbuffers.number_types.UOffsetTFlags.py_type(schematicId), 0)

def AddSchematicId(builder: flatbuffers.Builder, schematicId: int):
    TaskAddSchematicId(builder, schematicId)

def TaskEnd(builder: flatbuffers.Builder) -> int:
    return builder.EndObject()

def End(builder: flatbuffers.Builder) -> int:
    return TaskEnd(builder)