import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ArrowT } from './arrow';
import { DataCatalogT } from './data-catalog';
import { DriveT } from './drive';
import { Function, FunctionT } from './function';
import { GraphQueryT } from './graph-query';
import { PlaceholderT } from './placeholder';
import { QueryTableSourceT } from './query-table-source';
import { SetExpr, SetExprT } from './set-expr';
import { TableSourceUnion } from './table-source-union';
import { ValuesT } from './values';
import { VectorT } from './vector';
export declare class UpdateQueryElement implements flatbuffers.IUnpackableObject<UpdateQueryElementT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): UpdateQueryElement;
    static getRootAsUpdateQueryElement(bb: flatbuffers.ByteBuffer, obj?: UpdateQueryElement): UpdateQueryElement;
    static getSizePrefixedRootAsUpdateQueryElement(bb: flatbuffers.ByteBuffer, obj?: UpdateQueryElement): UpdateQueryElement;
    sourceType(): TableSourceUnion;
    source<T extends flatbuffers.Table>(obj: any): any | null;
    sets(index: number, obj?: SetExpr): SetExpr | null;
    setsLength(): number;
    filter(obj?: Function): Function | null;
    static startUpdateQueryElement(builder: flatbuffers.Builder): void;
    static addSourceType(builder: flatbuffers.Builder, sourceType: TableSourceUnion): void;
    static addSource(builder: flatbuffers.Builder, sourceOffset: flatbuffers.Offset): void;
    static addSets(builder: flatbuffers.Builder, setsOffset: flatbuffers.Offset): void;
    static createSetsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startSetsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addFilter(builder: flatbuffers.Builder, filterOffset: flatbuffers.Offset): void;
    static endUpdateQueryElement(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): UpdateQueryElementT;
    unpackTo(_o: UpdateQueryElementT): void;
}
export declare class UpdateQueryElementT implements flatbuffers.IGeneratedObject {
    sourceType: TableSourceUnion;
    source: ArrowT | DataCatalogT | DriveT | GraphQueryT | PlaceholderT | QueryTableSourceT | ValuesT | VectorT | null;
    sets: (SetExprT)[];
    filter: FunctionT | null;
    constructor(sourceType?: TableSourceUnion, source?: ArrowT | DataCatalogT | DriveT | GraphQueryT | PlaceholderT | QueryTableSourceT | ValuesT | VectorT | null, sets?: (SetExprT)[], filter?: FunctionT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=update-query-element.d.ts.map