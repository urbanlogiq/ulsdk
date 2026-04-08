import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ArrowT } from './arrow';
import { DataCatalogT } from './data-catalog';
import { DriveT } from './drive';
import { GraphQueryT } from './graph-query';
import { OnConflict, OnConflictT } from './on-conflict';
import { PlaceholderT } from './placeholder';
import { QueryElement, QueryElementT } from './query-element';
import { QueryTableSourceT } from './query-table-source';
import { TableSourceUnion } from './table-source-union';
import { ValuesT } from './values';
import { VectorT } from './vector';
export declare class InsertQueryElement implements flatbuffers.IUnpackableObject<InsertQueryElementT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): InsertQueryElement;
    static getRootAsInsertQueryElement(bb: flatbuffers.ByteBuffer, obj?: InsertQueryElement): InsertQueryElement;
    static getSizePrefixedRootAsInsertQueryElement(bb: flatbuffers.ByteBuffer, obj?: InsertQueryElement): InsertQueryElement;
    source(obj?: QueryElement): QueryElement | null;
    columns(index: number): string;
    columns(index: number, optionalEncoding: flatbuffers.Encoding): string | Uint8Array;
    columnsLength(): number;
    destType(): TableSourceUnion;
    dest<T extends flatbuffers.Table>(obj: any): any | null;
    onConflict(obj?: OnConflict): OnConflict | null;
    returning(index: number): string;
    returning(index: number, optionalEncoding: flatbuffers.Encoding): string | Uint8Array;
    returningLength(): number;
    static startInsertQueryElement(builder: flatbuffers.Builder): void;
    static addSource(builder: flatbuffers.Builder, sourceOffset: flatbuffers.Offset): void;
    static addColumns(builder: flatbuffers.Builder, columnsOffset: flatbuffers.Offset): void;
    static createColumnsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startColumnsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addDestType(builder: flatbuffers.Builder, destType: TableSourceUnion): void;
    static addDest(builder: flatbuffers.Builder, destOffset: flatbuffers.Offset): void;
    static addOnConflict(builder: flatbuffers.Builder, onConflictOffset: flatbuffers.Offset): void;
    static addReturning(builder: flatbuffers.Builder, returningOffset: flatbuffers.Offset): void;
    static createReturningVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startReturningVector(builder: flatbuffers.Builder, numElems: number): void;
    static endInsertQueryElement(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): InsertQueryElementT;
    unpackTo(_o: InsertQueryElementT): void;
}
export declare class InsertQueryElementT implements flatbuffers.IGeneratedObject {
    source: QueryElementT | null;
    columns: (string)[];
    destType: TableSourceUnion;
    dest: ArrowT | DataCatalogT | DriveT | GraphQueryT | PlaceholderT | QueryTableSourceT | ValuesT | VectorT | null;
    onConflict: OnConflictT | null;
    returning: (string)[];
    constructor(source?: QueryElementT | null, columns?: (string)[], destType?: TableSourceUnion, dest?: ArrowT | DataCatalogT | DriveT | GraphQueryT | PlaceholderT | QueryTableSourceT | ValuesT | VectorT | null, onConflict?: OnConflictT | null, returning?: (string)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=insert-query-element.d.ts.map