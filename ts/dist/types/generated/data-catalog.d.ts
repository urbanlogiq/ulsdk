import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ContentId, ContentIdT } from './content-id';
import { MvdbPartitionT } from './mvdb-partition';
import { ObjectId, ObjectIdT } from './object-id';
import { TablePartition } from './table-partition';
import { WorklogPartitionT } from './worklog-partition';
export declare class DataCatalog implements flatbuffers.IUnpackableObject<DataCatalogT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DataCatalog;
    static getRootAsDataCatalog(bb: flatbuffers.ByteBuffer, obj?: DataCatalog): DataCatalog;
    static getSizePrefixedRootAsDataCatalog(bb: flatbuffers.ByteBuffer, obj?: DataCatalog): DataCatalog;
    id(obj?: ObjectId): ObjectId | null;
    partitionType(): TablePartition;
    /**
     * The partition of the table to query; can be null.
     */
    partition<T extends flatbuffers.Table>(obj: any): any | null;
    revision(obj?: ContentId): ContentId | null;
    static startDataCatalog(builder: flatbuffers.Builder): void;
    static addId(builder: flatbuffers.Builder, idOffset: flatbuffers.Offset): void;
    static addPartitionType(builder: flatbuffers.Builder, partitionType: TablePartition): void;
    static addPartition(builder: flatbuffers.Builder, partitionOffset: flatbuffers.Offset): void;
    static addRevision(builder: flatbuffers.Builder, revisionOffset: flatbuffers.Offset): void;
    static endDataCatalog(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): DataCatalogT;
    unpackTo(_o: DataCatalogT): void;
}
export declare class DataCatalogT implements flatbuffers.IGeneratedObject {
    id: ObjectIdT | null;
    partitionType: TablePartition;
    partition: MvdbPartitionT | WorklogPartitionT | null;
    revision: ContentIdT | null;
    constructor(id?: ObjectIdT | null, partitionType?: TablePartition, partition?: MvdbPartitionT | WorklogPartitionT | null, revision?: ContentIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=data-catalog.d.ts.map