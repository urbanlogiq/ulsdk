import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ArrowT } from './arrow';
import { DataCatalogT } from './data-catalog';
import { DriveT } from './drive';
import { Function, FunctionT } from './function';
import { GraphQueryT } from './graph-query';
import { PlaceholderT } from './placeholder';
import { QueryTableSourceT } from './query-table-source';
import { TableSourceUnion } from './table-source-union';
import { ValuesT } from './values';
import { VectorT } from './vector';
export declare class DeleteQueryElement implements flatbuffers.IUnpackableObject<DeleteQueryElementT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DeleteQueryElement;
    static getRootAsDeleteQueryElement(bb: flatbuffers.ByteBuffer, obj?: DeleteQueryElement): DeleteQueryElement;
    static getSizePrefixedRootAsDeleteQueryElement(bb: flatbuffers.ByteBuffer, obj?: DeleteQueryElement): DeleteQueryElement;
    sourceType(): TableSourceUnion;
    source<T extends flatbuffers.Table>(obj: any): any | null;
    filter(obj?: Function): Function | null;
    static startDeleteQueryElement(builder: flatbuffers.Builder): void;
    static addSourceType(builder: flatbuffers.Builder, sourceType: TableSourceUnion): void;
    static addSource(builder: flatbuffers.Builder, sourceOffset: flatbuffers.Offset): void;
    static addFilter(builder: flatbuffers.Builder, filterOffset: flatbuffers.Offset): void;
    static endDeleteQueryElement(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): DeleteQueryElementT;
    unpackTo(_o: DeleteQueryElementT): void;
}
export declare class DeleteQueryElementT implements flatbuffers.IGeneratedObject {
    sourceType: TableSourceUnion;
    source: ArrowT | DataCatalogT | DriveT | GraphQueryT | PlaceholderT | QueryTableSourceT | ValuesT | VectorT | null;
    filter: FunctionT | null;
    constructor(sourceType?: TableSourceUnion, source?: ArrowT | DataCatalogT | DriveT | GraphQueryT | PlaceholderT | QueryTableSourceT | ValuesT | VectorT | null, filter?: FunctionT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=delete-query-element.d.ts.map