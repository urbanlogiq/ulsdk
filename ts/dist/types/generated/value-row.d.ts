import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Expr, ExprT } from './expr';
export declare class ValueRow implements flatbuffers.IUnpackableObject<ValueRowT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ValueRow;
    static getRootAsValueRow(bb: flatbuffers.ByteBuffer, obj?: ValueRow): ValueRow;
    static getSizePrefixedRootAsValueRow(bb: flatbuffers.ByteBuffer, obj?: ValueRow): ValueRow;
    row(index: number, obj?: Expr): Expr | null;
    rowLength(): number;
    static startValueRow(builder: flatbuffers.Builder): void;
    static addRow(builder: flatbuffers.Builder, rowOffset: flatbuffers.Offset): void;
    static createRowVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startRowVector(builder: flatbuffers.Builder, numElems: number): void;
    static endValueRow(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createValueRow(builder: flatbuffers.Builder, rowOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ValueRowT;
    unpackTo(_o: ValueRowT): void;
}
export declare class ValueRowT implements flatbuffers.IGeneratedObject {
    row: (ExprT)[];
    constructor(row?: (ExprT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=value-row.d.ts.map