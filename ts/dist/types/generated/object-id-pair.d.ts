import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
export declare class ObjectIdPair implements flatbuffers.IUnpackableObject<ObjectIdPairT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ObjectIdPair;
    static getRootAsObjectIdPair(bb: flatbuffers.ByteBuffer, obj?: ObjectIdPair): ObjectIdPair;
    static getSizePrefixedRootAsObjectIdPair(bb: flatbuffers.ByteBuffer, obj?: ObjectIdPair): ObjectIdPair;
    id(obj?: ObjectId): ObjectId | null;
    object(index: number): number | null;
    objectLength(): number;
    objectArray(): Uint8Array | null;
    static startObjectIdPair(builder: flatbuffers.Builder): void;
    static addId(builder: flatbuffers.Builder, idOffset: flatbuffers.Offset): void;
    static addObject(builder: flatbuffers.Builder, objectOffset: flatbuffers.Offset): void;
    static createObjectVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startObjectVector(builder: flatbuffers.Builder, numElems: number): void;
    static endObjectIdPair(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createObjectIdPair(builder: flatbuffers.Builder, idOffset: flatbuffers.Offset, objectOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ObjectIdPairT;
    unpackTo(_o: ObjectIdPairT): void;
}
export declare class ObjectIdPairT implements flatbuffers.IGeneratedObject {
    id: ObjectIdT | null;
    object: (number)[];
    constructor(id?: ObjectIdT | null, object?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=object-id-pair.d.ts.map