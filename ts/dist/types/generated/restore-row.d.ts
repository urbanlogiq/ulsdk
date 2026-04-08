import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { GenericId, GenericIdT } from './generic-id';
/**
 * The RestoreRow operation restore a deleted row in the table
 * "Restore" is implemented by setting the value of the `ul_keep` system column to true.
 * This means that formerly "removed" rows are no longer treated as "removed" and will then be returned by queries.
 */
export declare class RestoreRow implements flatbuffers.IUnpackableObject<RestoreRowT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): RestoreRow;
    static getRootAsRestoreRow(bb: flatbuffers.ByteBuffer, obj?: RestoreRow): RestoreRow;
    static getSizePrefixedRootAsRestoreRow(bb: flatbuffers.ByteBuffer, obj?: RestoreRow): RestoreRow;
    /**
     * The value of the ul_node_id column, which uniquely identifies the row.
     */
    row(obj?: GenericId): GenericId | null;
    static startRestoreRow(builder: flatbuffers.Builder): void;
    static addRow(builder: flatbuffers.Builder, rowOffset: flatbuffers.Offset): void;
    static endRestoreRow(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createRestoreRow(builder: flatbuffers.Builder, rowOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): RestoreRowT;
    unpackTo(_o: RestoreRowT): void;
}
export declare class RestoreRowT implements flatbuffers.IGeneratedObject {
    row: GenericIdT | null;
    constructor(row?: GenericIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=restore-row.d.ts.map