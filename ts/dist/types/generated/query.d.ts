import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Explain, ExplainT } from './explain';
import { QueryElement, QueryElementT } from './query-element';
import { TableSourceInstance, TableSourceInstanceT } from './table-source-instance';
import { ValueInstance, ValueInstanceT } from './value-instance';
export declare class Query implements flatbuffers.IUnpackableObject<QueryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Query;
    static getRootAsQuery(bb: flatbuffers.ByteBuffer, obj?: Query): Query;
    static getSizePrefixedRootAsQuery(bb: flatbuffers.ByteBuffer, obj?: Query): Query;
    query(obj?: QueryElement): QueryElement | null;
    values(index: number, obj?: ValueInstance): ValueInstance | null;
    valuesLength(): number;
    limit(): number;
    boundSources(index: number, obj?: TableSourceInstance): TableSourceInstance | null;
    boundSourcesLength(): number;
    explain(obj?: Explain): Explain | null;
    static startQuery(builder: flatbuffers.Builder): void;
    static addQuery(builder: flatbuffers.Builder, queryOffset: flatbuffers.Offset): void;
    static addValues(builder: flatbuffers.Builder, valuesOffset: flatbuffers.Offset): void;
    static createValuesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startValuesVector(builder: flatbuffers.Builder, numElems: number): void;
    static addLimit(builder: flatbuffers.Builder, limit: number): void;
    static addBoundSources(builder: flatbuffers.Builder, boundSourcesOffset: flatbuffers.Offset): void;
    static createBoundSourcesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startBoundSourcesVector(builder: flatbuffers.Builder, numElems: number): void;
    static addExplain(builder: flatbuffers.Builder, explainOffset: flatbuffers.Offset): void;
    static endQuery(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): QueryT;
    unpackTo(_o: QueryT): void;
}
export declare class QueryT implements flatbuffers.IGeneratedObject {
    query: QueryElementT | null;
    values: (ValueInstanceT)[];
    limit: number;
    boundSources: (TableSourceInstanceT)[];
    explain: ExplainT | null;
    constructor(query?: QueryElementT | null, values?: (ValueInstanceT)[], limit?: number, boundSources?: (TableSourceInstanceT)[], explain?: ExplainT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=query.d.ts.map