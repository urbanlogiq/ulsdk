import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class UIntBucket implements flatbuffers.IUnpackableObject<UIntBucketT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): UIntBucket;
    count(): bigint;
    max(): bigint;
    static sizeOf(): number;
    static createUIntBucket(builder: flatbuffers.Builder, count: bigint, max: bigint): flatbuffers.Offset;
    unpack(): UIntBucketT;
    unpackTo(_o: UIntBucketT): void;
}
export declare class UIntBucketT implements flatbuffers.IGeneratedObject {
    count: bigint;
    max: bigint;
    constructor(count?: bigint, max?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=uint-bucket.d.ts.map