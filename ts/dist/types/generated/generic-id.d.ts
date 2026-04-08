import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class GenericId implements flatbuffers.IUnpackableObject<GenericIdT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): GenericId;
    static getRootAsGenericId(bb: flatbuffers.ByteBuffer, obj?: GenericId): GenericId;
    static getSizePrefixedRootAsGenericId(bb: flatbuffers.ByteBuffer, obj?: GenericId): GenericId;
    b(index: number): number | null;
    bLength(): number;
    bArray(): Uint8Array | null;
    static startGenericId(builder: flatbuffers.Builder): void;
    static addB(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): void;
    static createBVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startBVector(builder: flatbuffers.Builder, numElems: number): void;
    static endGenericId(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createGenericId(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): GenericIdT;
    unpackTo(_o: GenericIdT): void;
}
export declare class GenericIdT implements flatbuffers.IGeneratedObject {
    b: (number)[];
    constructor(b?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=generic-id.d.ts.map