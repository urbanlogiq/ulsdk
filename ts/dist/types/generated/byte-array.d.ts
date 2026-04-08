import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class ByteArray implements flatbuffers.IUnpackableObject<ByteArrayT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ByteArray;
    static getRootAsByteArray(bb: flatbuffers.ByteBuffer, obj?: ByteArray): ByteArray;
    static getSizePrefixedRootAsByteArray(bb: flatbuffers.ByteBuffer, obj?: ByteArray): ByteArray;
    b(index: number): number | null;
    bLength(): number;
    bArray(): Uint8Array | null;
    static startByteArray(builder: flatbuffers.Builder): void;
    static addB(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): void;
    static createBVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startBVector(builder: flatbuffers.Builder, numElems: number): void;
    static endByteArray(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createByteArray(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ByteArrayT;
    unpackTo(_o: ByteArrayT): void;
}
export declare class ByteArrayT implements flatbuffers.IGeneratedObject {
    b: (number)[];
    constructor(b?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=byte-array.d.ts.map