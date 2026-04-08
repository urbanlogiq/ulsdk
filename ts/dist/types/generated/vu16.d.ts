import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VU16 implements flatbuffers.IUnpackableObject<VU16T> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VU16;
    static getRootAsVU16(bb: flatbuffers.ByteBuffer, obj?: VU16): VU16;
    static getSizePrefixedRootAsVU16(bb: flatbuffers.ByteBuffer, obj?: VU16): VU16;
    v(): number;
    static startVU16(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: number): void;
    static endVU16(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVU16(builder: flatbuffers.Builder, v: number): flatbuffers.Offset;
    unpack(): VU16T;
    unpackTo(_o: VU16T): void;
}
export declare class VU16T implements flatbuffers.IGeneratedObject {
    v: number;
    constructor(v?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vu16.d.ts.map