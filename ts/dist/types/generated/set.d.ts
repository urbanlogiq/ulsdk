import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { GenericId, GenericIdT } from './generic-id';
import { ValueInstance, ValueInstanceT } from './value-instance';
/**
 * The Set operation is used to set the value of a cell in a table.
 */
export declare class Set implements flatbuffers.IUnpackableObject<SetT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Set;
    static getRootAsSet(bb: flatbuffers.ByteBuffer, obj?: Set): Set;
    static getSizePrefixedRootAsSet(bb: flatbuffers.ByteBuffer, obj?: Set): Set;
    /**
     * The value of the ul_node_id column, which uniquely identifies the row.
     */
    row(obj?: GenericId): GenericId | null;
    /**
     * Name of the column to set.
     */
    col(): string | null;
    col(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    /**
     * The value to set.
     */
    value(obj?: ValueInstance): ValueInstance | null;
    static startSet(builder: flatbuffers.Builder): void;
    static addRow(builder: flatbuffers.Builder, rowOffset: flatbuffers.Offset): void;
    static addCol(builder: flatbuffers.Builder, colOffset: flatbuffers.Offset): void;
    static addValue(builder: flatbuffers.Builder, valueOffset: flatbuffers.Offset): void;
    static endSet(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): SetT;
    unpackTo(_o: SetT): void;
}
export declare class SetT implements flatbuffers.IGeneratedObject {
    row: GenericIdT | null;
    col: string | Uint8Array | null;
    value: ValueInstanceT | null;
    constructor(row?: GenericIdT | null, col?: string | Uint8Array | null, value?: ValueInstanceT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=set.d.ts.map