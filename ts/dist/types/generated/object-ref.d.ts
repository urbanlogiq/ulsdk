import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { DataCatalogObjectTy } from './data-catalog-object-ty';
import { ObjectId, ObjectIdT } from './object-id';
export declare class ObjectRef implements flatbuffers.IUnpackableObject<ObjectRefT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ObjectRef;
    static getRootAsObjectRef(bb: flatbuffers.ByteBuffer, obj?: ObjectRef): ObjectRef;
    static getSizePrefixedRootAsObjectRef(bb: flatbuffers.ByteBuffer, obj?: ObjectRef): ObjectRef;
    id(obj?: ObjectId): ObjectId | null;
    ty(): DataCatalogObjectTy;
    static startObjectRef(builder: flatbuffers.Builder): void;
    static addId(builder: flatbuffers.Builder, idOffset: flatbuffers.Offset): void;
    static addTy(builder: flatbuffers.Builder, ty: DataCatalogObjectTy): void;
    static endObjectRef(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createObjectRef(builder: flatbuffers.Builder, idOffset: flatbuffers.Offset, ty: DataCatalogObjectTy): flatbuffers.Offset;
    unpack(): ObjectRefT;
    unpackTo(_o: ObjectRefT): void;
}
export declare class ObjectRefT implements flatbuffers.IGeneratedObject {
    id: ObjectIdT | null;
    ty: DataCatalogObjectTy;
    constructor(id?: ObjectIdT | null, ty?: DataCatalogObjectTy);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=object-ref.d.ts.map