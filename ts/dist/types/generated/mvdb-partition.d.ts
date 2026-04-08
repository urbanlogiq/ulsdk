import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * Some multiverse databases are partitioned, and we need to refer to a specific
 * partition within the database. This is used for that purpose.
 */
export declare class MvdbPartition implements flatbuffers.IUnpackableObject<MvdbPartitionT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): MvdbPartition;
    static getRootAsMvdbPartition(bb: flatbuffers.ByteBuffer, obj?: MvdbPartition): MvdbPartition;
    static getSizePrefixedRootAsMvdbPartition(bb: flatbuffers.ByteBuffer, obj?: MvdbPartition): MvdbPartition;
    partition(): string | null;
    partition(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startMvdbPartition(builder: flatbuffers.Builder): void;
    static addPartition(builder: flatbuffers.Builder, partitionOffset: flatbuffers.Offset): void;
    static endMvdbPartition(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createMvdbPartition(builder: flatbuffers.Builder, partitionOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): MvdbPartitionT;
    unpackTo(_o: MvdbPartitionT): void;
}
export declare class MvdbPartitionT implements flatbuffers.IGeneratedObject {
    partition: string | Uint8Array | null;
    constructor(partition?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=mvdb-partition.d.ts.map