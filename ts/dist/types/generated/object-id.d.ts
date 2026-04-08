import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class ObjectId implements flatbuffers.IUnpackableObject<ObjectIdT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ObjectId;
    static getRootAsObjectId(bb: flatbuffers.ByteBuffer, obj?: ObjectId): ObjectId;
    static getSizePrefixedRootAsObjectId(bb: flatbuffers.ByteBuffer, obj?: ObjectId): ObjectId;
    b(index: number): number | null;
    bLength(): number;
    bArray(): Uint8Array | null;
    static startObjectId(builder: flatbuffers.Builder): void;
    static addB(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): void;
    static createBVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startBVector(builder: flatbuffers.Builder, numElems: number): void;
    static endObjectId(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createObjectId(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ObjectIdT;
    unpackTo(_o: ObjectIdT): void;
}
export declare class ObjectIdT implements flatbuffers.IGeneratedObject {
    b: (number)[];
    constructor(b?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=object-id.d.ts.map