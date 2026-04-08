import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { GenericId, GenericIdT } from './generic-id';
export declare class Restore implements flatbuffers.IUnpackableObject<RestoreT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Restore;
    static getRootAsRestore(bb: flatbuffers.ByteBuffer, obj?: Restore): Restore;
    static getSizePrefixedRootAsRestore(bb: flatbuffers.ByteBuffer, obj?: Restore): Restore;
    row(obj?: GenericId): GenericId | null;
    static startRestore(builder: flatbuffers.Builder): void;
    static addRow(builder: flatbuffers.Builder, rowOffset: flatbuffers.Offset): void;
    static endRestore(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createRestore(builder: flatbuffers.Builder, rowOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): RestoreT;
    unpackTo(_o: RestoreT): void;
}
export declare class RestoreT implements flatbuffers.IGeneratedObject {
    row: GenericIdT | null;
    constructor(row?: GenericIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=restore.d.ts.map