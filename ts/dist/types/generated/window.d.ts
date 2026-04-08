import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Expr, ExprT } from './expr';
import { Function, FunctionT } from './function';
import { OrderBy, OrderByT } from './order-by';
export declare class Window implements flatbuffers.IUnpackableObject<WindowT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Window;
    static getRootAsWindow(bb: flatbuffers.ByteBuffer, obj?: Window): Window;
    static getSizePrefixedRootAsWindow(bb: flatbuffers.ByteBuffer, obj?: Window): Window;
    fun(obj?: Function): Function | null;
    partition(index: number, obj?: Expr): Expr | null;
    partitionLength(): number;
    orderBy(index: number, obj?: OrderBy): OrderBy | null;
    orderByLength(): number;
    static startWindow(builder: flatbuffers.Builder): void;
    static addFun(builder: flatbuffers.Builder, funOffset: flatbuffers.Offset): void;
    static addPartition(builder: flatbuffers.Builder, partitionOffset: flatbuffers.Offset): void;
    static createPartitionVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startPartitionVector(builder: flatbuffers.Builder, numElems: number): void;
    static addOrderBy(builder: flatbuffers.Builder, orderByOffset: flatbuffers.Offset): void;
    static createOrderByVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startOrderByVector(builder: flatbuffers.Builder, numElems: number): void;
    static endWindow(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createWindow(builder: flatbuffers.Builder, funOffset: flatbuffers.Offset, partitionOffset: flatbuffers.Offset, orderByOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): WindowT;
    unpackTo(_o: WindowT): void;
}
export declare class WindowT implements flatbuffers.IGeneratedObject {
    fun: FunctionT | null;
    partition: (ExprT)[];
    orderBy: (OrderByT)[];
    constructor(fun?: FunctionT | null, partition?: (ExprT)[], orderBy?: (OrderByT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=window.d.ts.map