import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectIdPair, ObjectIdPairT } from './object-id-pair';
export declare class ObjectIdPairList implements flatbuffers.IUnpackableObject<ObjectIdPairListT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ObjectIdPairList;
    static getRootAsObjectIdPairList(bb: flatbuffers.ByteBuffer, obj?: ObjectIdPairList): ObjectIdPairList;
    static getSizePrefixedRootAsObjectIdPairList(bb: flatbuffers.ByteBuffer, obj?: ObjectIdPairList): ObjectIdPairList;
    pairs(index: number, obj?: ObjectIdPair): ObjectIdPair | null;
    pairsLength(): number;
    static startObjectIdPairList(builder: flatbuffers.Builder): void;
    static addPairs(builder: flatbuffers.Builder, pairsOffset: flatbuffers.Offset): void;
    static createPairsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startPairsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endObjectIdPairList(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createObjectIdPairList(builder: flatbuffers.Builder, pairsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ObjectIdPairListT;
    unpackTo(_o: ObjectIdPairListT): void;
}
export declare class ObjectIdPairListT implements flatbuffers.IGeneratedObject {
    pairs: (ObjectIdPairT)[];
    constructor(pairs?: (ObjectIdPairT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=object-id-pair-list.d.ts.map