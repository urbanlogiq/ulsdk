import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class Sha256 implements flatbuffers.IUnpackableObject<Sha256T> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Sha256;
    static getRootAsSha256(bb: flatbuffers.ByteBuffer, obj?: Sha256): Sha256;
    static getSizePrefixedRootAsSha256(bb: flatbuffers.ByteBuffer, obj?: Sha256): Sha256;
    b(index: number): number | null;
    bLength(): number;
    bArray(): Uint8Array | null;
    static startSha256(builder: flatbuffers.Builder): void;
    static addB(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): void;
    static createBVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startBVector(builder: flatbuffers.Builder, numElems: number): void;
    static endSha256(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createSha256(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): Sha256T;
    unpackTo(_o: Sha256T): void;
}
export declare class Sha256T implements flatbuffers.IGeneratedObject {
    b: (number)[];
    constructor(b?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=sha256.d.ts.map