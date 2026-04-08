import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VF64 implements flatbuffers.IUnpackableObject<VF64T> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VF64;
    static getRootAsVF64(bb: flatbuffers.ByteBuffer, obj?: VF64): VF64;
    static getSizePrefixedRootAsVF64(bb: flatbuffers.ByteBuffer, obj?: VF64): VF64;
    v(): number;
    static startVF64(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: number): void;
    static endVF64(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVF64(builder: flatbuffers.Builder, v: number): flatbuffers.Offset;
    unpack(): VF64T;
    unpackTo(_o: VF64T): void;
}
export declare class VF64T implements flatbuffers.IGeneratedObject {
    v: number;
    constructor(v?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vf64.d.ts.map