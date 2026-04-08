import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class IntBucket implements flatbuffers.IUnpackableObject<IntBucketT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): IntBucket;
    count(): bigint;
    max(): bigint;
    static sizeOf(): number;
    static createIntBucket(builder: flatbuffers.Builder, count: bigint, max: bigint): flatbuffers.Offset;
    unpack(): IntBucketT;
    unpackTo(_o: IntBucketT): void;
}
export declare class IntBucketT implements flatbuffers.IGeneratedObject {
    count: bigint;
    max: bigint;
    constructor(count?: bigint, max?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=int-bucket.d.ts.map