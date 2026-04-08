import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ArrowT } from './arrow';
import { DataCatalogT } from './data-catalog';
import { DriveT } from './drive';
import { GraphQueryT } from './graph-query';
import { PlaceholderT } from './placeholder';
import { QueryTableSourceT } from './query-table-source';
import { TableSourceUnion } from './table-source-union';
import { ValuesT } from './values';
import { VectorT } from './vector';
export declare class TableSourceInstance implements flatbuffers.IUnpackableObject<TableSourceInstanceT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): TableSourceInstance;
    static getRootAsTableSourceInstance(bb: flatbuffers.ByteBuffer, obj?: TableSourceInstance): TableSourceInstance;
    static getSizePrefixedRootAsTableSourceInstance(bb: flatbuffers.ByteBuffer, obj?: TableSourceInstance): TableSourceInstance;
    tType(): TableSourceUnion;
    t<T extends flatbuffers.Table>(obj: any): any | null;
    static startTableSourceInstance(builder: flatbuffers.Builder): void;
    static addTType(builder: flatbuffers.Builder, tType: TableSourceUnion): void;
    static addT(builder: flatbuffers.Builder, tOffset: flatbuffers.Offset): void;
    static endTableSourceInstance(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createTableSourceInstance(builder: flatbuffers.Builder, tType: TableSourceUnion, tOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): TableSourceInstanceT;
    unpackTo(_o: TableSourceInstanceT): void;
}
export declare class TableSourceInstanceT implements flatbuffers.IGeneratedObject {
    tType: TableSourceUnion;
    t: ArrowT | DataCatalogT | DriveT | GraphQueryT | PlaceholderT | QueryTableSourceT | ValuesT | VectorT | null;
    constructor(tType?: TableSourceUnion, t?: ArrowT | DataCatalogT | DriveT | GraphQueryT | PlaceholderT | QueryTableSourceT | ValuesT | VectorT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=table-source-instance.d.ts.map