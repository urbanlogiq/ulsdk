import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Expr, ExprT } from './expr';
export declare class Partition implements flatbuffers.IUnpackableObject<PartitionT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Partition;
    static getRootAsPartition(bb: flatbuffers.ByteBuffer, obj?: Partition): Partition;
    static getSizePrefixedRootAsPartition(bb: flatbuffers.ByteBuffer, obj?: Partition): Partition;
    expr(obj?: Expr): Expr | null;
    static startPartition(builder: flatbuffers.Builder): void;
    static addExpr(builder: flatbuffers.Builder, exprOffset: flatbuffers.Offset): void;
    static endPartition(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createPartition(builder: flatbuffers.Builder, exprOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): PartitionT;
    unpackTo(_o: PartitionT): void;
}
export declare class PartitionT implements flatbuffers.IGeneratedObject {
    expr: ExprT | null;
    constructor(expr?: ExprT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=partition.d.ts.map