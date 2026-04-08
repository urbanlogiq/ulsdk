import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Query, QueryT } from './query';
export declare class QueryTableSource implements flatbuffers.IUnpackableObject<QueryTableSourceT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): QueryTableSource;
    static getRootAsQueryTableSource(bb: flatbuffers.ByteBuffer, obj?: QueryTableSource): QueryTableSource;
    static getSizePrefixedRootAsQueryTableSource(bb: flatbuffers.ByteBuffer, obj?: QueryTableSource): QueryTableSource;
    q(obj?: Query): Query | null;
    static startQueryTableSource(builder: flatbuffers.Builder): void;
    static addQ(builder: flatbuffers.Builder, qOffset: flatbuffers.Offset): void;
    static endQueryTableSource(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createQueryTableSource(builder: flatbuffers.Builder, qOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): QueryTableSourceT;
    unpackTo(_o: QueryTableSourceT): void;
}
export declare class QueryTableSourceT implements flatbuffers.IGeneratedObject {
    q: QueryT | null;
    constructor(q?: QueryT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=query-table-source.d.ts.map