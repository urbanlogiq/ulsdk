import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { QueryElement, QueryElementT } from './query-element';
import { QueryElementOp } from './query-element-op';
export declare class BinaryQueryElement implements flatbuffers.IUnpackableObject<BinaryQueryElementT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): BinaryQueryElement;
    static getRootAsBinaryQueryElement(bb: flatbuffers.ByteBuffer, obj?: BinaryQueryElement): BinaryQueryElement;
    static getSizePrefixedRootAsBinaryQueryElement(bb: flatbuffers.ByteBuffer, obj?: BinaryQueryElement): BinaryQueryElement;
    op(): QueryElementOp;
    lhs(obj?: QueryElement): QueryElement | null;
    rhs(obj?: QueryElement): QueryElement | null;
    static startBinaryQueryElement(builder: flatbuffers.Builder): void;
    static addOp(builder: flatbuffers.Builder, op: QueryElementOp): void;
    static addLhs(builder: flatbuffers.Builder, lhsOffset: flatbuffers.Offset): void;
    static addRhs(builder: flatbuffers.Builder, rhsOffset: flatbuffers.Offset): void;
    static endBinaryQueryElement(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): BinaryQueryElementT;
    unpackTo(_o: BinaryQueryElementT): void;
}
export declare class BinaryQueryElementT implements flatbuffers.IGeneratedObject {
    op: QueryElementOp;
    lhs: QueryElementT | null;
    rhs: QueryElementT | null;
    constructor(op?: QueryElementOp, lhs?: QueryElementT | null, rhs?: QueryElementT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=binary-query-element.d.ts.map