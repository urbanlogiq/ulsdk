import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { GenericId, GenericIdT } from './generic-id';
export declare class Delete implements flatbuffers.IUnpackableObject<DeleteT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Delete;
    static getRootAsDelete(bb: flatbuffers.ByteBuffer, obj?: Delete): Delete;
    static getSizePrefixedRootAsDelete(bb: flatbuffers.ByteBuffer, obj?: Delete): Delete;
    row(obj?: GenericId): GenericId | null;
    static startDelete(builder: flatbuffers.Builder): void;
    static addRow(builder: flatbuffers.Builder, rowOffset: flatbuffers.Offset): void;
    static endDelete(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDelete(builder: flatbuffers.Builder, rowOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DeleteT;
    unpackTo(_o: DeleteT): void;
}
export declare class DeleteT implements flatbuffers.IGeneratedObject {
    row: GenericIdT | null;
    constructor(row?: GenericIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=delete.d.ts.map