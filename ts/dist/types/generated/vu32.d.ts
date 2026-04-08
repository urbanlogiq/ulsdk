import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VU32 implements flatbuffers.IUnpackableObject<VU32T> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VU32;
    static getRootAsVU32(bb: flatbuffers.ByteBuffer, obj?: VU32): VU32;
    static getSizePrefixedRootAsVU32(bb: flatbuffers.ByteBuffer, obj?: VU32): VU32;
    v(): number;
    static startVU32(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: number): void;
    static endVU32(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVU32(builder: flatbuffers.Builder, v: number): flatbuffers.Offset;
    unpack(): VU32T;
    unpackTo(_o: VU32T): void;
}
export declare class VU32T implements flatbuffers.IGeneratedObject {
    v: number;
    constructor(v?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vu32.d.ts.map