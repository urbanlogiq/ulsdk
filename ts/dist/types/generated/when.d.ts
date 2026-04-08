import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Expr, ExprT } from './expr';
export declare class When implements flatbuffers.IUnpackableObject<WhenT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): When;
    static getRootAsWhen(bb: flatbuffers.ByteBuffer, obj?: When): When;
    static getSizePrefixedRootAsWhen(bb: flatbuffers.ByteBuffer, obj?: When): When;
    cond(obj?: Expr): Expr | null;
    value(obj?: Expr): Expr | null;
    static startWhen(builder: flatbuffers.Builder): void;
    static addCond(builder: flatbuffers.Builder, condOffset: flatbuffers.Offset): void;
    static addValue(builder: flatbuffers.Builder, valueOffset: flatbuffers.Offset): void;
    static endWhen(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): WhenT;
    unpackTo(_o: WhenT): void;
}
export declare class WhenT implements flatbuffers.IGeneratedObject {
    cond: ExprT | null;
    value: ExprT | null;
    constructor(cond?: ExprT | null, value?: ExprT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=when.d.ts.map