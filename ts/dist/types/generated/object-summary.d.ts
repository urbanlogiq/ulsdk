import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ContentId, ContentIdT } from './content-id';
import { DataCatalogObjectTy } from './data-catalog-object-ty';
import { ObjectId, ObjectIdT } from './object-id';
export declare class ObjectSummary implements flatbuffers.IUnpackableObject<ObjectSummaryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ObjectSummary;
    static getRootAsObjectSummary(bb: flatbuffers.ByteBuffer, obj?: ObjectSummary): ObjectSummary;
    static getSizePrefixedRootAsObjectSummary(bb: flatbuffers.ByteBuffer, obj?: ObjectSummary): ObjectSummary;
    id(obj?: ObjectId): ObjectId | null;
    headRevision(obj?: ContentId): ContentId | null;
    ty(): DataCatalogObjectTy;
    time(): bigint;
    acl(obj?: ObjectId): ObjectId | null;
    driveSize(): bigint;
    static startObjectSummary(builder: flatbuffers.Builder): void;
    static addId(builder: flatbuffers.Builder, idOffset: flatbuffers.Offset): void;
    static addHeadRevision(builder: flatbuffers.Builder, headRevisionOffset: flatbuffers.Offset): void;
    static addTy(builder: flatbuffers.Builder, ty: DataCatalogObjectTy): void;
    static addTime(builder: flatbuffers.Builder, time: bigint): void;
    static addAcl(builder: flatbuffers.Builder, aclOffset: flatbuffers.Offset): void;
    static addDriveSize(builder: flatbuffers.Builder, driveSize: bigint): void;
    static endObjectSummary(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): ObjectSummaryT;
    unpackTo(_o: ObjectSummaryT): void;
}
export declare class ObjectSummaryT implements flatbuffers.IGeneratedObject {
    id: ObjectIdT | null;
    headRevision: ContentIdT | null;
    ty: DataCatalogObjectTy;
    time: bigint;
    acl: ObjectIdT | null;
    driveSize: bigint;
    constructor(id?: ObjectIdT | null, headRevision?: ContentIdT | null, ty?: DataCatalogObjectTy, time?: bigint, acl?: ObjectIdT | null, driveSize?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=object-summary.d.ts.map