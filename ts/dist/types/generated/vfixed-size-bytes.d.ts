import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VFixedSizeBytes implements flatbuffers.IUnpackableObject<VFixedSizeBytesT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VFixedSizeBytes;
    static getRootAsVFixedSizeBytes(bb: flatbuffers.ByteBuffer, obj?: VFixedSizeBytes): VFixedSizeBytes;
    static getSizePrefixedRootAsVFixedSizeBytes(bb: flatbuffers.ByteBuffer, obj?: VFixedSizeBytes): VFixedSizeBytes;
    v(index: number): number | null;
    vLength(): number;
    vArray(): Uint8Array | null;
    sz(): number;
    static startVFixedSizeBytes(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, vOffset: flatbuffers.Offset): void;
    static createVVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startVVector(builder: flatbuffers.Builder, numElems: number): void;
    static addSz(builder: flatbuffers.Builder, sz: number): void;
    static endVFixedSizeBytes(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVFixedSizeBytes(builder: flatbuffers.Builder, vOffset: flatbuffers.Offset, sz: number): flatbuffers.Offset;
    unpack(): VFixedSizeBytesT;
    unpackTo(_o: VFixedSizeBytesT): void;
}
export declare class VFixedSizeBytesT implements flatbuffers.IGeneratedObject {
    v: (number)[];
    sz: number;
    constructor(v?: (number)[], sz?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vfixed-size-bytes.d.ts.map