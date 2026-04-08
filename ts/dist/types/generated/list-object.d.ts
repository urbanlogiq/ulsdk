import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { DataCatalogObjectTy } from './data-catalog-object-ty';
import { ObjectId, ObjectIdT } from './object-id';
export declare class ListObject implements flatbuffers.IUnpackableObject<ListObjectT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ListObject;
    static getRootAsListObject(bb: flatbuffers.ByteBuffer, obj?: ListObject): ListObject;
    static getSizePrefixedRootAsListObject(bb: flatbuffers.ByteBuffer, obj?: ListObject): ListObject;
    id(obj?: ObjectId): ObjectId | null;
    ty(): DataCatalogObjectTy;
    size(): bigint;
    static startListObject(builder: flatbuffers.Builder): void;
    static addId(builder: flatbuffers.Builder, idOffset: flatbuffers.Offset): void;
    static addTy(builder: flatbuffers.Builder, ty: DataCatalogObjectTy): void;
    static addSize(builder: flatbuffers.Builder, size: bigint): void;
    static endListObject(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createListObject(builder: flatbuffers.Builder, idOffset: flatbuffers.Offset, ty: DataCatalogObjectTy, size: bigint): flatbuffers.Offset;
    unpack(): ListObjectT;
    unpackTo(_o: ListObjectT): void;
}
export declare class ListObjectT implements flatbuffers.IGeneratedObject {
    id: ObjectIdT | null;
    ty: DataCatalogObjectTy;
    size: bigint;
    constructor(id?: ObjectIdT | null, ty?: DataCatalogObjectTy, size?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=list-object.d.ts.map