import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { NullableUint, NullableUintT } from './nullable-uint';
import { TypeHint } from './type-hint';
export declare class Column implements flatbuffers.IUnpackableObject<ColumnT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Column;
    static getRootAsColumn(bb: flatbuffers.ByteBuffer, obj?: Column): Column;
    static getSizePrefixedRootAsColumn(bb: flatbuffers.ByteBuffer, obj?: Column): Column;
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    typeHint(): TypeHint;
    source(obj?: NullableUint): NullableUint | null;
    static startColumn(builder: flatbuffers.Builder): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static addTypeHint(builder: flatbuffers.Builder, typeHint: TypeHint): void;
    static addSource(builder: flatbuffers.Builder, sourceOffset: flatbuffers.Offset): void;
    static endColumn(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): ColumnT;
    unpackTo(_o: ColumnT): void;
}
export declare class ColumnT implements flatbuffers.IGeneratedObject {
    name: string | Uint8Array | null;
    typeHint: TypeHint;
    source: NullableUintT | null;
    constructor(name?: string | Uint8Array | null, typeHint?: TypeHint, source?: NullableUintT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=column.d.ts.map