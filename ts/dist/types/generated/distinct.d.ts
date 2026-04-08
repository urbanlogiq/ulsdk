import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Expr, ExprT } from './expr';
/**
 * The Distinct function defined in fun.fbs is for use in cases like:
 * SELECT COUNT(DISTINCT c0), SUM(c1) FROM t GROUP BY c2;
 * The `distinct` field here on the query element is to be used to remove duplicate rows, like:
 * SELECT DISTINCT * FROM t;
 * or
 * SELECT DISTINCT ON (c0, c1) FROM t;
 */
export declare class Distinct implements flatbuffers.IUnpackableObject<DistinctT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Distinct;
    static getRootAsDistinct(bb: flatbuffers.ByteBuffer, obj?: Distinct): Distinct;
    static getSizePrefixedRootAsDistinct(bb: flatbuffers.ByteBuffer, obj?: Distinct): Distinct;
    /**
     * If `on` is unset or has length 0, then the distinct is:
     * SELECT DISTINCT * FROM t;
     * If `on` has length > 0, then distinct is:
     * SELECT DISTINCT ON (c0, c1) FROM t;
     */
    on(index: number, obj?: Expr): Expr | null;
    onLength(): number;
    static startDistinct(builder: flatbuffers.Builder): void;
    static addOn(builder: flatbuffers.Builder, onOffset: flatbuffers.Offset): void;
    static createOnVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startOnVector(builder: flatbuffers.Builder, numElems: number): void;
    static endDistinct(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDistinct(builder: flatbuffers.Builder, onOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DistinctT;
    unpackTo(_o: DistinctT): void;
}
export declare class DistinctT implements flatbuffers.IGeneratedObject {
    on: (ExprT)[];
    constructor(on?: (ExprT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=distinct.d.ts.map