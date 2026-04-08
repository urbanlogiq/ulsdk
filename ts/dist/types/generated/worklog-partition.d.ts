import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class WorklogPartition implements flatbuffers.IUnpackableObject<WorklogPartitionT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): WorklogPartition;
    static getRootAsWorklogPartition(bb: flatbuffers.ByteBuffer, obj?: WorklogPartition): WorklogPartition;
    static getSizePrefixedRootAsWorklogPartition(bb: flatbuffers.ByteBuffer, obj?: WorklogPartition): WorklogPartition;
    idx(): number;
    static startWorklogPartition(builder: flatbuffers.Builder): void;
    static addIdx(builder: flatbuffers.Builder, idx: number): void;
    static endWorklogPartition(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createWorklogPartition(builder: flatbuffers.Builder, idx: number): flatbuffers.Offset;
    unpack(): WorklogPartitionT;
    unpackTo(_o: WorklogPartitionT): void;
}
export declare class WorklogPartitionT implements flatbuffers.IGeneratedObject {
    idx: number;
    constructor(idx?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=worklog-partition.d.ts.map