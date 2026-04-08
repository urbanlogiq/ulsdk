import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { OrderBy, OrderByT } from './order-by';
export declare class OrderByExpr implements flatbuffers.IUnpackableObject<OrderByExprT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): OrderByExpr;
    static getRootAsOrderByExpr(bb: flatbuffers.ByteBuffer, obj?: OrderByExpr): OrderByExpr;
    static getSizePrefixedRootAsOrderByExpr(bb: flatbuffers.ByteBuffer, obj?: OrderByExpr): OrderByExpr;
    orderBy(index: number, obj?: OrderBy): OrderBy | null;
    orderByLength(): number;
    static startOrderByExpr(builder: flatbuffers.Builder): void;
    static addOrderBy(builder: flatbuffers.Builder, orderByOffset: flatbuffers.Offset): void;
    static createOrderByVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startOrderByVector(builder: flatbuffers.Builder, numElems: number): void;
    static endOrderByExpr(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createOrderByExpr(builder: flatbuffers.Builder, orderByOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): OrderByExprT;
    unpackTo(_o: OrderByExprT): void;
}
export declare class OrderByExprT implements flatbuffers.IGeneratedObject {
    orderBy: (OrderByT)[];
    constructor(orderBy?: (OrderByT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=order-by-expr.d.ts.map