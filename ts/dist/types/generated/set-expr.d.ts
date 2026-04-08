import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Expr, ExprT } from './expr';
/**
 * SetExprs represent the expressions used as part of an UPDATE-type operation
 */
export declare class SetExpr implements flatbuffers.IUnpackableObject<SetExprT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): SetExpr;
    static getRootAsSetExpr(bb: flatbuffers.ByteBuffer, obj?: SetExpr): SetExpr;
    static getSizePrefixedRootAsSetExpr(bb: flatbuffers.ByteBuffer, obj?: SetExpr): SetExpr;
    /**
     * Because we cannot refer to multiple tables at once in a single UPDATE
     * operation we only need to name the column, we can just a string here
     * instead of a Column table.
     */
    col(): string | null;
    col(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    /**
     * This is the expression that is evaluted to produce the value that is
     * assigned to the column named in the `col` field.
     */
    expr(obj?: Expr): Expr | null;
    static startSetExpr(builder: flatbuffers.Builder): void;
    static addCol(builder: flatbuffers.Builder, colOffset: flatbuffers.Offset): void;
    static addExpr(builder: flatbuffers.Builder, exprOffset: flatbuffers.Offset): void;
    static endSetExpr(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): SetExprT;
    unpackTo(_o: SetExprT): void;
}
export declare class SetExprT implements flatbuffers.IGeneratedObject {
    col: string | Uint8Array | null;
    expr: ExprT | null;
    constructor(col?: string | Uint8Array | null, expr?: ExprT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=set-expr.d.ts.map