import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Expr, ExprT } from './expr';
import { When, WhenT } from './when';
export declare class Case implements flatbuffers.IUnpackableObject<CaseT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Case;
    static getRootAsCase(bb: flatbuffers.ByteBuffer, obj?: Case): Case;
    static getSizePrefixedRootAsCase(bb: flatbuffers.ByteBuffer, obj?: Case): Case;
    when(index: number, obj?: When): When | null;
    whenLength(): number;
    else_(obj?: Expr): Expr | null;
    static startCase(builder: flatbuffers.Builder): void;
    static addWhen(builder: flatbuffers.Builder, whenOffset: flatbuffers.Offset): void;
    static createWhenVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startWhenVector(builder: flatbuffers.Builder, numElems: number): void;
    static addElse(builder: flatbuffers.Builder, else_Offset: flatbuffers.Offset): void;
    static endCase(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): CaseT;
    unpackTo(_o: CaseT): void;
}
export declare class CaseT implements flatbuffers.IGeneratedObject {
    when: (WhenT)[];
    else_: ExprT | null;
    constructor(when?: (WhenT)[], else_?: ExprT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=case.d.ts.map