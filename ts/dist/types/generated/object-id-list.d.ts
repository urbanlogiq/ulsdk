import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
export declare class ObjectIdList implements flatbuffers.IUnpackableObject<ObjectIdListT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ObjectIdList;
    static getRootAsObjectIdList(bb: flatbuffers.ByteBuffer, obj?: ObjectIdList): ObjectIdList;
    static getSizePrefixedRootAsObjectIdList(bb: flatbuffers.ByteBuffer, obj?: ObjectIdList): ObjectIdList;
    ids(index: number, obj?: ObjectId): ObjectId | null;
    idsLength(): number;
    static startObjectIdList(builder: flatbuffers.Builder): void;
    static addIds(builder: flatbuffers.Builder, idsOffset: flatbuffers.Offset): void;
    static createIdsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startIdsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endObjectIdList(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createObjectIdList(builder: flatbuffers.Builder, idsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ObjectIdListT;
    unpackTo(_o: ObjectIdListT): void;
}
export declare class ObjectIdListT implements flatbuffers.IGeneratedObject {
    ids: (ObjectIdT)[];
    constructor(ids?: (ObjectIdT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=object-id-list.d.ts.map