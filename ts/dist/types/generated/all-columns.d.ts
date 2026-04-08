import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { NullableUint, NullableUintT } from './nullable-uint';
export declare class AllColumns implements flatbuffers.IUnpackableObject<AllColumnsT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): AllColumns;
    static getRootAsAllColumns(bb: flatbuffers.ByteBuffer, obj?: AllColumns): AllColumns;
    static getSizePrefixedRootAsAllColumns(bb: flatbuffers.ByteBuffer, obj?: AllColumns): AllColumns;
    source(obj?: NullableUint): NullableUint | null;
    static startAllColumns(builder: flatbuffers.Builder): void;
    static addSource(builder: flatbuffers.Builder, sourceOffset: flatbuffers.Offset): void;
    static endAllColumns(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createAllColumns(builder: flatbuffers.Builder, sourceOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): AllColumnsT;
    unpackTo(_o: AllColumnsT): void;
}
export declare class AllColumnsT implements flatbuffers.IGeneratedObject {
    source: NullableUintT | null;
    constructor(source?: NullableUintT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=all-columns.d.ts.map