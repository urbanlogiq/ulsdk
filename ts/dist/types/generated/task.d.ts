import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
import { ParamIndices, ParamIndicesT } from './param-indices';
import { Status } from './status';
import { TaskErrorTy } from './task-error-ty';
export declare class Task implements flatbuffers.IUnpackableObject<TaskT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Task;
    static getRootAsTask(bb: flatbuffers.ByteBuffer, obj?: Task): Task;
    static getSizePrefixedRootAsTask(bb: flatbuffers.ByteBuffer, obj?: Task): Task;
    _Id(obj?: ObjectId): ObjectId | null;
    /**
     * User who created the job. This is the same as the user_id field in the
     * job structure but duplicated for convenience when looking up task related
     * information.
     */
    userId(obj?: ObjectId): ObjectId | null;
    /**
     * Task object, either a source or a stream
     */
    task(obj?: ObjectId): ObjectId | null;
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    /**
     * Associated Job ID
     */
    jobId(obj?: ObjectId): ObjectId | null;
    /**
     * Task status
     */
    status(): Status;
    /**
     * For errors, generic information.
     */
    message(): string | null;
    message(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    /**
     * Parameter indices taken from the RunSpec for this particular task step.
     */
    params(obj?: ParamIndices): ParamIndices | null;
    /**
     * The output of this step. If the task is computational (ie: not just a
     * data stream lookup) this is a blank object where the results will be
     * written. If it is a lookup of an existing stream, this will be populated
     * with the stream ID
     */
    output(obj?: ObjectId): ObjectId | null;
    /**
     * If false, keep this object if it's a temporary/intermediate after job
     * creation. This must not be set if the output object above is a provided
     * stream.
     */
    discard(): boolean;
    /**
     * The upstream nodes that enabled this task
     */
    upstream(index: number, obj?: ObjectId): ObjectId | null;
    upstreamLength(): number;
    /**
     * The downstream nodes to enable once this task is complete
     */
    downstream(index: number, obj?: ObjectId): ObjectId | null;
    downstreamLength(): number;
    /**
     * Task creation time, in ms-since-Unix-epoch UTC.
     */
    created(): bigint;
    /**
     * Task start time, in ms-since-Unix-epoch UTC.
     */
    start(): bigint;
    /**
     * Task last poll time, in ms-since-Unix-epoch UTC.
     */
    lastUpdated(): bigint;
    end(): bigint;
    retries(): number;
    barrierCount(): number;
    lastUpdatedByPod(): string | null;
    lastUpdatedByPod(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    flags(): number;
    errorTy(): TaskErrorTy;
    schematicId(obj?: ObjectId): ObjectId | null;
    static startTask(builder: flatbuffers.Builder): void;
    static add_id(builder: flatbuffers.Builder, _IdOffset: flatbuffers.Offset): void;
    static addUserId(builder: flatbuffers.Builder, userIdOffset: flatbuffers.Offset): void;
    static addTask(builder: flatbuffers.Builder, taskOffset: flatbuffers.Offset): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static addJobId(builder: flatbuffers.Builder, jobIdOffset: flatbuffers.Offset): void;
    static addStatus(builder: flatbuffers.Builder, status: Status): void;
    static addMessage(builder: flatbuffers.Builder, messageOffset: flatbuffers.Offset): void;
    static addParams(builder: flatbuffers.Builder, paramsOffset: flatbuffers.Offset): void;
    static addOutput(builder: flatbuffers.Builder, outputOffset: flatbuffers.Offset): void;
    static addDiscard(builder: flatbuffers.Builder, discard: boolean): void;
    static addUpstream(builder: flatbuffers.Builder, upstreamOffset: flatbuffers.Offset): void;
    static createUpstreamVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startUpstreamVector(builder: flatbuffers.Builder, numElems: number): void;
    static addDownstream(builder: flatbuffers.Builder, downstreamOffset: flatbuffers.Offset): void;
    static createDownstreamVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startDownstreamVector(builder: flatbuffers.Builder, numElems: number): void;
    static addCreated(builder: flatbuffers.Builder, created: bigint): void;
    static addStart(builder: flatbuffers.Builder, start: bigint): void;
    static addLastUpdated(builder: flatbuffers.Builder, lastUpdated: bigint): void;
    static addEnd(builder: flatbuffers.Builder, end: bigint): void;
    static addRetries(builder: flatbuffers.Builder, retries: number): void;
    static addBarrierCount(builder: flatbuffers.Builder, barrierCount: number): void;
    static addLastUpdatedByPod(builder: flatbuffers.Builder, lastUpdatedByPodOffset: flatbuffers.Offset): void;
    static addFlags(builder: flatbuffers.Builder, flags: number): void;
    static addErrorTy(builder: flatbuffers.Builder, errorTy: TaskErrorTy): void;
    static addSchematicId(builder: flatbuffers.Builder, schematicIdOffset: flatbuffers.Offset): void;
    static endTask(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): TaskT;
    unpackTo(_o: TaskT): void;
}
export declare class TaskT implements flatbuffers.IGeneratedObject {
    _Id: ObjectIdT | null;
    userId: ObjectIdT | null;
    task: ObjectIdT | null;
    name: string | Uint8Array | null;
    jobId: ObjectIdT | null;
    status: Status;
    message: string | Uint8Array | null;
    params: ParamIndicesT | null;
    output: ObjectIdT | null;
    discard: boolean;
    upstream: (ObjectIdT)[];
    downstream: (ObjectIdT)[];
    created: bigint;
    start: bigint;
    lastUpdated: bigint;
    end: bigint;
    retries: number;
    barrierCount: number;
    lastUpdatedByPod: string | Uint8Array | null;
    flags: number;
    errorTy: TaskErrorTy;
    schematicId: ObjectIdT | null;
    constructor(_Id?: ObjectIdT | null, userId?: ObjectIdT | null, task?: ObjectIdT | null, name?: string | Uint8Array | null, jobId?: ObjectIdT | null, status?: Status, message?: string | Uint8Array | null, params?: ParamIndicesT | null, output?: ObjectIdT | null, discard?: boolean, upstream?: (ObjectIdT)[], downstream?: (ObjectIdT)[], created?: bigint, start?: bigint, lastUpdated?: bigint, end?: bigint, retries?: number, barrierCount?: number, lastUpdatedByPod?: string | Uint8Array | null, flags?: number, errorTy?: TaskErrorTy, schematicId?: ObjectIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=task.d.ts.map