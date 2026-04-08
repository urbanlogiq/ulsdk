import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class FloatBucket implements flatbuffers.IUnpackableObject<FloatBucketT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): FloatBucket;
    count(): bigint;
    max(): number;
    static sizeOf(): number;
    static createFloatBucket(builder: flatbuffers.Builder, count: bigint, max: number): flatbuffers.Offset;
    unpack(): FloatBucketT;
    unpackTo(_o: FloatBucketT): void;
}
export declare class FloatBucketT implements flatbuffers.IGeneratedObject {
    count: bigint;
    max: number;
    constructor(count?: bigint, max?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=float-bucket.d.ts.map