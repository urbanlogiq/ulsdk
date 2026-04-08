import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
import { SchemaT } from './schema';
import { TableFrom } from './table-from';
/**
 * Body parameter for POST datacatalog/table
 */
export declare class NewTable implements flatbuffers.IUnpackableObject<NewTableT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NewTable;
    static getRootAsNewTable(bb: flatbuffers.ByteBuffer, obj?: NewTable): NewTable;
    static getSizePrefixedRootAsNewTable(bb: flatbuffers.ByteBuffer, obj?: NewTable): NewTable;
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    /**
     * Parent drive directory in which the table is to be created.
     */
    parent(obj?: ObjectId): ObjectId | null;
    /**
     * If specified, creates a new table using this as the object ID.
     */
    target(obj?: ObjectId): ObjectId | null;
    /**
     * If true, data will be copied into the new table from the source ID
     * provided.
     */
    migrate(): boolean;
    fromType(): TableFrom;
    /**
     * The base to use for the table. If an object ID is provided, this will
     * take the schema from the provided stream or metadata object. If a
     * schema is provided, the table will be created, empty, from that.
     */
    from<T extends flatbuffers.Table>(obj: any): any | null;
    static startNewTable(builder: flatbuffers.Builder): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static addParent(builder: flatbuffers.Builder, parentOffset: flatbuffers.Offset): void;
    static addTarget(builder: flatbuffers.Builder, targetOffset: flatbuffers.Offset): void;
    static addMigrate(builder: flatbuffers.Builder, migrate: boolean): void;
    static addFromType(builder: flatbuffers.Builder, fromType: TableFrom): void;
    static addFrom(builder: flatbuffers.Builder, fromOffset: flatbuffers.Offset): void;
    static endNewTable(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): NewTableT;
    unpackTo(_o: NewTableT): void;
}
export declare class NewTableT implements flatbuffers.IGeneratedObject {
    name: string | Uint8Array | null;
    parent: ObjectIdT | null;
    target: ObjectIdT | null;
    migrate: boolean;
    fromType: TableFrom;
    from: ObjectIdT | SchemaT | null;
    constructor(name?: string | Uint8Array | null, parent?: ObjectIdT | null, target?: ObjectIdT | null, migrate?: boolean, fromType?: TableFrom, from?: ObjectIdT | SchemaT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=new-table.d.ts.map