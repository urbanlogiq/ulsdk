import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VBytes implements flatbuffers.IUnpackableObject<VBytesT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VBytes;
    static getRootAsVBytes(bb: flatbuffers.ByteBuffer, obj?: VBytes): VBytes;
    static getSizePrefixedRootAsVBytes(bb: flatbuffers.ByteBuffer, obj?: VBytes): VBytes;
    v(index: number): number | null;
    vLength(): number;
    vArray(): Uint8Array | null;
    static startVBytes(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, vOffset: flatbuffers.Offset): void;
    static createVVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startVVector(builder: flatbuffers.Builder, numElems: number): void;
    static endVBytes(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVBytes(builder: flatbuffers.Builder, vOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): VBytesT;
    unpackTo(_o: VBytesT): void;
}
export declare class VBytesT implements flatbuffers.IGeneratedObject {
    v: (number)[];
    constructor(v?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vbytes.d.ts.map