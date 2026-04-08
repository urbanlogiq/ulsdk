import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class B2cId implements flatbuffers.IUnpackableObject<B2cIdT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): B2cId;
    static getRootAsB2cId(bb: flatbuffers.ByteBuffer, obj?: B2cId): B2cId;
    static getSizePrefixedRootAsB2cId(bb: flatbuffers.ByteBuffer, obj?: B2cId): B2cId;
    b(index: number): number | null;
    bLength(): number;
    bArray(): Uint8Array | null;
    static startB2cId(builder: flatbuffers.Builder): void;
    static addB(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): void;
    static createBVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startBVector(builder: flatbuffers.Builder, numElems: number): void;
    static endB2cId(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createB2cId(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): B2cIdT;
    unpackTo(_o: B2cIdT): void;
}
export declare class B2cIdT implements flatbuffers.IGeneratedObject {
    b: (number)[];
    constructor(b?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=b2c-id.d.ts.map