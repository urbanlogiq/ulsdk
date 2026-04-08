import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VF32 implements flatbuffers.IUnpackableObject<VF32T> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VF32;
    static getRootAsVF32(bb: flatbuffers.ByteBuffer, obj?: VF32): VF32;
    static getSizePrefixedRootAsVF32(bb: flatbuffers.ByteBuffer, obj?: VF32): VF32;
    v(): number;
    static startVF32(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: number): void;
    static endVF32(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVF32(builder: flatbuffers.Builder, v: number): flatbuffers.Offset;
    unpack(): VF32T;
    unpackTo(_o: VF32T): void;
}
export declare class VF32T implements flatbuffers.IGeneratedObject {
    v: number;
    constructor(v?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vf32.d.ts.map