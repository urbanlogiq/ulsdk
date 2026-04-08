import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { GenericId, GenericIdT } from './generic-id';
import { ValueInstance, ValueInstanceT } from './value-instance';
export declare class Modify implements flatbuffers.IUnpackableObject<ModifyT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Modify;
    static getRootAsModify(bb: flatbuffers.ByteBuffer, obj?: Modify): Modify;
    static getSizePrefixedRootAsModify(bb: flatbuffers.ByteBuffer, obj?: Modify): Modify;
    col(): string | null;
    col(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    value(obj?: ValueInstance): ValueInstance | null;
    previous(obj?: ValueInstance): ValueInstance | null;
    row(obj?: GenericId): GenericId | null;
    static startModify(builder: flatbuffers.Builder): void;
    static addCol(builder: flatbuffers.Builder, colOffset: flatbuffers.Offset): void;
    static addValue(builder: flatbuffers.Builder, valueOffset: flatbuffers.Offset): void;
    static addPrevious(builder: flatbuffers.Builder, previousOffset: flatbuffers.Offset): void;
    static addRow(builder: flatbuffers.Builder, rowOffset: flatbuffers.Offset): void;
    static endModify(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): ModifyT;
    unpackTo(_o: ModifyT): void;
}
export declare class ModifyT implements flatbuffers.IGeneratedObject {
    col: string | Uint8Array | null;
    value: ValueInstanceT | null;
    previous: ValueInstanceT | null;
    row: GenericIdT | null;
    constructor(col?: string | Uint8Array | null, value?: ValueInstanceT | null, previous?: ValueInstanceT | null, row?: GenericIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=modify.d.ts.map