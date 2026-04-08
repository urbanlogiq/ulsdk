import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VU8 implements flatbuffers.IUnpackableObject<VU8T> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VU8;
    static getRootAsVU8(bb: flatbuffers.ByteBuffer, obj?: VU8): VU8;
    static getSizePrefixedRootAsVU8(bb: flatbuffers.ByteBuffer, obj?: VU8): VU8;
    v(): number;
    static startVU8(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: number): void;
    static endVU8(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVU8(builder: flatbuffers.Builder, v: number): flatbuffers.Offset;
    unpack(): VU8T;
    unpackTo(_o: VU8T): void;
}
export declare class VU8T implements flatbuffers.IGeneratedObject {
    v: number;
    constructor(v?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vu8.d.ts.map