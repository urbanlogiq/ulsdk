import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { AllColumnsT } from './all-columns';
import { CaseT } from './case';
import { ColumnT } from './column';
import { ExprUnion } from './expr-union';
import { FunctionT } from './function';
import { OrderByExprT } from './order-by-expr';
import { PartitionT } from './partition';
import { UnsetArgumentT } from './unset-argument';
import { ValueIndexT } from './value-index';
import { ValueNameT } from './value-name';
import { WindowT } from './window';
export declare class Expr implements flatbuffers.IUnpackableObject<ExprT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Expr;
    static getRootAsExpr(bb: flatbuffers.ByteBuffer, obj?: Expr): Expr;
    static getSizePrefixedRootAsExpr(bb: flatbuffers.ByteBuffer, obj?: Expr): Expr;
    exprsType(): ExprUnion;
    exprs<T extends flatbuffers.Table>(obj: any): any | null;
    static startExpr(builder: flatbuffers.Builder): void;
    static addExprsType(builder: flatbuffers.Builder, exprsType: ExprUnion): void;
    static addExprs(builder: flatbuffers.Builder, exprsOffset: flatbuffers.Offset): void;
    static endExpr(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createExpr(builder: flatbuffers.Builder, exprsType: ExprUnion, exprsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ExprT;
    unpackTo(_o: ExprT): void;
}
export declare class ExprT implements flatbuffers.IGeneratedObject {
    exprsType: ExprUnion;
    exprs: AllColumnsT | CaseT | ColumnT | FunctionT | OrderByExprT | PartitionT | UnsetArgumentT | ValueIndexT | ValueNameT | WindowT | null;
    constructor(exprsType?: ExprUnion, exprs?: AllColumnsT | CaseT | ColumnT | FunctionT | OrderByExprT | PartitionT | UnsetArgumentT | ValueIndexT | ValueNameT | WindowT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=expr.d.ts.map