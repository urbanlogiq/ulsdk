import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VU64 implements flatbuffers.IUnpackableObject<VU64T> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VU64;
    static getRootAsVU64(bb: flatbuffers.ByteBuffer, obj?: VU64): VU64;
    static getSizePrefixedRootAsVU64(bb: flatbuffers.ByteBuffer, obj?: VU64): VU64;
    v(): bigint;
    static startVU64(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: bigint): void;
    static endVU64(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVU64(builder: flatbuffers.Builder, v: bigint): flatbuffers.Offset;
    unpack(): VU64T;
    unpackTo(_o: VU64T): void;
}
export declare class VU64T implements flatbuffers.IGeneratedObject {
    v: bigint;
    constructor(v?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vu64.d.ts.map