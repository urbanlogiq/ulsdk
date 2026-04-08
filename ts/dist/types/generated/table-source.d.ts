import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ArrowT } from './arrow';
import { DataCatalogT } from './data-catalog';
import { DriveT } from './drive';
import { Expr, ExprT } from './expr';
import { Function, FunctionT } from './function';
import { GraphQueryT } from './graph-query';
import { OrderBy, OrderByT } from './order-by';
import { PlaceholderT } from './placeholder';
import { QueryTableSourceT } from './query-table-source';
import { TableSourceUnion } from './table-source-union';
import { ValuesT } from './values';
import { VectorT } from './vector';
export declare class TableSource implements flatbuffers.IUnpackableObject<TableSourceT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): TableSource;
    static getRootAsTableSource(bb: flatbuffers.ByteBuffer, obj?: TableSource): TableSource;
    static getSizePrefixedRootAsTableSource(bb: flatbuffers.ByteBuffer, obj?: TableSource): TableSource;
    tType(): TableSourceUnion;
    t<T extends flatbuffers.Table>(obj: any): any | null;
    fields(index: number, obj?: Expr): Expr | null;
    fieldsLength(): number;
    filter(obj?: Function): Function | null;
    orderBy(index: number, obj?: OrderBy): OrderBy | null;
    orderByLength(): number;
    groupBy(index: number, obj?: Expr): Expr | null;
    groupByLength(): number;
    static startTableSource(builder: flatbuffers.Builder): void;
    static addTType(builder: flatbuffers.Builder, tType: TableSourceUnion): void;
    static addT(builder: flatbuffers.Builder, tOffset: flatbuffers.Offset): void;
    static addFields(builder: flatbuffers.Builder, fieldsOffset: flatbuffers.Offset): void;
    static createFieldsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startFieldsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addFilter(builder: flatbuffers.Builder, filterOffset: flatbuffers.Offset): void;
    static addOrderBy(builder: flatbuffers.Builder, orderByOffset: flatbuffers.Offset): void;
    static createOrderByVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startOrderByVector(builder: flatbuffers.Builder, numElems: number): void;
    static addGroupBy(builder: flatbuffers.Builder, groupByOffset: flatbuffers.Offset): void;
    static createGroupByVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startGroupByVector(builder: flatbuffers.Builder, numElems: number): void;
    static endTableSource(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): TableSourceT;
    unpackTo(_o: TableSourceT): void;
}
export declare class TableSourceT implements flatbuffers.IGeneratedObject {
    tType: TableSourceUnion;
    t: ArrowT | DataCatalogT | DriveT | GraphQueryT | PlaceholderT | QueryTableSourceT | ValuesT | VectorT | null;
    fields: (ExprT)[];
    filter: FunctionT | null;
    orderBy: (OrderByT)[];
    groupBy: (ExprT)[];
    constructor(tType?: TableSourceUnion, t?: ArrowT | DataCatalogT | DriveT | GraphQueryT | PlaceholderT | QueryTableSourceT | ValuesT | VectorT | null, fields?: (ExprT)[], filter?: FunctionT | null, orderBy?: (OrderByT)[], groupBy?: (ExprT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=table-source.d.ts.map