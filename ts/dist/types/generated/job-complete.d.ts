import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
export declare class JobComplete implements flatbuffers.IUnpackableObject<JobCompleteT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): JobComplete;
    static getRootAsJobComplete(bb: flatbuffers.ByteBuffer, obj?: JobComplete): JobComplete;
    static getSizePrefixedRootAsJobComplete(bb: flatbuffers.ByteBuffer, obj?: JobComplete): JobComplete;
    job(obj?: ObjectId): ObjectId | null;
    static startJobComplete(builder: flatbuffers.Builder): void;
    static addJob(builder: flatbuffers.Builder, jobOffset: flatbuffers.Offset): void;
    static endJobComplete(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createJobComplete(builder: flatbuffers.Builder, jobOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): JobCompleteT;
    unpackTo(_o: JobCompleteT): void;
}
export declare class JobCompleteT implements flatbuffers.IGeneratedObject {
    job: ObjectIdT | null;
    constructor(job?: ObjectIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=job-complete.d.ts.map