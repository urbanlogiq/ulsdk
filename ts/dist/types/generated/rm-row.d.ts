import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { GenericId, GenericIdT } from './generic-id';
/**
 * The RmRow operation is used to remove a row from a table.
 */
export declare class RmRow implements flatbuffers.IUnpackableObject<RmRowT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): RmRow;
    static getRootAsRmRow(bb: flatbuffers.ByteBuffer, obj?: RmRow): RmRow;
    static getSizePrefixedRootAsRmRow(bb: flatbuffers.ByteBuffer, obj?: RmRow): RmRow;
    /**
     * The value of the ul_node_id column, which uniquely identifies the row.
     */
    row(obj?: GenericId): GenericId | null;
    static startRmRow(builder: flatbuffers.Builder): void;
    static addRow(builder: flatbuffers.Builder, rowOffset: flatbuffers.Offset): void;
    static endRmRow(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createRmRow(builder: flatbuffers.Builder, rowOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): RmRowT;
    unpackTo(_o: RmRowT): void;
}
export declare class RmRowT implements flatbuffers.IGeneratedObject {
    row: GenericIdT | null;
    constructor(row?: GenericIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=rm-row.d.ts.map