import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { OrderBy, OrderByT } from './order-by';
import { QueryPathElement, QueryPathElementT } from './query-path-element';
/**
 * The GraphQuery encapsulates the entire world graph query.
 */
export declare class GraphQuery implements flatbuffers.IUnpackableObject<GraphQueryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): GraphQuery;
    static getRootAsGraphQuery(bb: flatbuffers.ByteBuffer, obj?: GraphQuery): GraphQuery;
    static getSizePrefixedRootAsGraphQuery(bb: flatbuffers.ByteBuffer, obj?: GraphQuery): GraphQuery;
    path(index: number, obj?: QueryPathElement): QueryPathElement | null;
    pathLength(): number;
    limit(): number;
    orderBy(index: number, obj?: OrderBy): OrderBy | null;
    orderByLength(): number;
    static startGraphQuery(builder: flatbuffers.Builder): void;
    static addPath(builder: flatbuffers.Builder, pathOffset: flatbuffers.Offset): void;
    static createPathVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startPathVector(builder: flatbuffers.Builder, numElems: number): void;
    static addLimit(builder: flatbuffers.Builder, limit: number): void;
    static addOrderBy(builder: flatbuffers.Builder, orderByOffset: flatbuffers.Offset): void;
    static createOrderByVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startOrderByVector(builder: flatbuffers.Builder, numElems: number): void;
    static endGraphQuery(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createGraphQuery(builder: flatbuffers.Builder, pathOffset: flatbuffers.Offset, limit: number, orderByOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): GraphQueryT;
    unpackTo(_o: GraphQueryT): void;
}
export declare class GraphQueryT implements flatbuffers.IGeneratedObject {
    path: (QueryPathElementT)[];
    limit: number;
    orderBy: (OrderByT)[];
    constructor(path?: (QueryPathElementT)[], limit?: number, orderBy?: (OrderByT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=graph-query.d.ts.map