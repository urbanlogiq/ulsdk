import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { BinaryQueryElementT } from './binary-query-element';
import { DeleteQueryElementT } from './delete-query-element';
import { InsertQueryElementT } from './insert-query-element';
import { QueryElementUnion } from './query-element-union';
import { UnaryQueryElementT } from './unary-query-element';
import { UpdateQueryElementT } from './update-query-element';
export declare class QueryElement implements flatbuffers.IUnpackableObject<QueryElementT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): QueryElement;
    static getRootAsQueryElement(bb: flatbuffers.ByteBuffer, obj?: QueryElement): QueryElement;
    static getSizePrefixedRootAsQueryElement(bb: flatbuffers.ByteBuffer, obj?: QueryElement): QueryElement;
    qType(): QueryElementUnion;
    q<T extends flatbuffers.Table>(obj: any): any | null;
    static startQueryElement(builder: flatbuffers.Builder): void;
    static addQType(builder: flatbuffers.Builder, qType: QueryElementUnion): void;
    static addQ(builder: flatbuffers.Builder, qOffset: flatbuffers.Offset): void;
    static endQueryElement(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createQueryElement(builder: flatbuffers.Builder, qType: QueryElementUnion, qOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): QueryElementT;
    unpackTo(_o: QueryElementT): void;
}
export declare class QueryElementT implements flatbuffers.IGeneratedObject {
    qType: QueryElementUnion;
    q: BinaryQueryElementT | DeleteQueryElementT | InsertQueryElementT | UnaryQueryElementT | UpdateQueryElementT | null;
    constructor(qType?: QueryElementUnion, q?: BinaryQueryElementT | DeleteQueryElementT | InsertQueryElementT | UnaryQueryElementT | UpdateQueryElementT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=query-element.d.ts.map