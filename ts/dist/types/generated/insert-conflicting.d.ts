import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * This variant is for selecting the default behavior of an INSERT statement
 * where there may be conflicts; it inserts the rows if there is a conflict.
 */
export declare class InsertConflicting implements flatbuffers.IUnpackableObject<InsertConflictingT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): InsertConflicting;
    static getRootAsInsertConflicting(bb: flatbuffers.ByteBuffer, obj?: InsertConflicting): InsertConflicting;
    static getSizePrefixedRootAsInsertConflicting(bb: flatbuffers.ByteBuffer, obj?: InsertConflicting): InsertConflicting;
    static startInsertConflicting(builder: flatbuffers.Builder): void;
    static endInsertConflicting(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createInsertConflicting(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): InsertConflictingT;
    unpackTo(_o: InsertConflictingT): void;
}
export declare class InsertConflictingT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=insert-conflicting.d.ts.map