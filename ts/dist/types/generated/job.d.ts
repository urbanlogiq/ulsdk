import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Attr, AttrT } from './attr';
import { ObjectId, ObjectIdT } from './object-id';
import { Status } from './status';
import { Task, TaskT } from './task';
import { TaskErrorTy } from './task-error-ty';
import { TaskParameter, TaskParameterT } from './task-parameter';
export declare class Job implements flatbuffers.IUnpackableObject<JobT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Job;
    static getRootAsJob(bb: flatbuffers.ByteBuffer, obj?: Job): Job;
    static getSizePrefixedRootAsJob(bb: flatbuffers.ByteBuffer, obj?: Job): Job;
    /**
     * Is the job complete?
     */
    status(): Status;
    /**
     * User ID who created this job.
     */
    userId(obj?: ObjectId): ObjectId | null;
    /**
     * A list of all the tasks that constitute this job.
     */
    tasks(index: number, obj?: Task): Task | null;
    tasksLength(): number;
    /**
     * Parameters verbatim from the RunSpec
     */
    params(index: number, obj?: TaskParameter): TaskParameter | null;
    paramsLength(): number;
    errorTys(index: number): TaskErrorTy | null;
    errorTysLength(): number;
    errorTysArray(): Int32Array | null;
    attributes(index: number, obj?: Attr): Attr | null;
    attributesLength(): number;
    static startJob(builder: flatbuffers.Builder): void;
    static addStatus(builder: flatbuffers.Builder, status: Status): void;
    static addUserId(builder: flatbuffers.Builder, userIdOffset: flatbuffers.Offset): void;
    static addTasks(builder: flatbuffers.Builder, tasksOffset: flatbuffers.Offset): void;
    static createTasksVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startTasksVector(builder: flatbuffers.Builder, numElems: number): void;
    static addParams(builder: flatbuffers.Builder, paramsOffset: flatbuffers.Offset): void;
    static createParamsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startParamsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addErrorTys(builder: flatbuffers.Builder, errorTysOffset: flatbuffers.Offset): void;
    static createErrorTysVector(builder: flatbuffers.Builder, data: TaskErrorTy[]): flatbuffers.Offset;
    static startErrorTysVector(builder: flatbuffers.Builder, numElems: number): void;
    static addAttributes(builder: flatbuffers.Builder, attributesOffset: flatbuffers.Offset): void;
    static createAttributesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startAttributesVector(builder: flatbuffers.Builder, numElems: number): void;
    static endJob(builder: flatbuffers.Builder): flatbuffers.Offset;
    static finishJobBuffer(builder: flatbuffers.Builder, offset: flatbuffers.Offset): void;
    static finishSizePrefixedJobBuffer(builder: flatbuffers.Builder, offset: flatbuffers.Offset): void;
    unpack(): JobT;
    unpackTo(_o: JobT): void;
}
export declare class JobT implements flatbuffers.IGeneratedObject {
    status: Status;
    userId: ObjectIdT | null;
    tasks: (TaskT)[];
    params: (TaskParameterT)[];
    errorTys: (TaskErrorTy)[];
    attributes: (AttrT)[];
    constructor(status?: Status, userId?: ObjectIdT | null, tasks?: (TaskT)[], params?: (TaskParameterT)[], errorTys?: (TaskErrorTy)[], attributes?: (AttrT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=job.d.ts.map