import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ValueRow, ValueRowT } from './value-row';
export declare class Values implements flatbuffers.IUnpackableObject<ValuesT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Values;
    static getRootAsValues(bb: flatbuffers.ByteBuffer, obj?: Values): Values;
    static getSizePrefixedRootAsValues(bb: flatbuffers.ByteBuffer, obj?: Values): Values;
    rows(index: number, obj?: ValueRow): ValueRow | null;
    rowsLength(): number;
    static startValues(builder: flatbuffers.Builder): void;
    static addRows(builder: flatbuffers.Builder, rowsOffset: flatbuffers.Offset): void;
    static createRowsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startRowsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endValues(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createValues(builder: flatbuffers.Builder, rowsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ValuesT;
    unpackTo(_o: ValuesT): void;
}
export declare class ValuesT implements flatbuffers.IGeneratedObject {
    rows: (ValueRowT)[];
    constructor(rows?: (ValueRowT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=values.d.ts.map