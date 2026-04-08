import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { OrderBy, OrderByT } from './order-by';
export declare class TableOrderBy implements flatbuffers.IUnpackableObject<TableOrderByT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): TableOrderBy;
    static getRootAsTableOrderBy(bb: flatbuffers.ByteBuffer, obj?: TableOrderBy): TableOrderBy;
    static getSizePrefixedRootAsTableOrderBy(bb: flatbuffers.ByteBuffer, obj?: TableOrderBy): TableOrderBy;
    source(): number;
    orderBy(obj?: OrderBy): OrderBy | null;
    /**
     * Because the `source` field defaults to 0 when unset, use this field to
     * indicate whether the source should be used. In some cases, such as when
     * you want to order by an column produced by aggregating on the result of
     * a join, the column isn't associated with any table source.
     *
     * In that case, set `use_source` to false and the verbatim string provided
     * in the `field` field of the `OrderBy` structure will be used for the order-by.
     */
    useSource(): boolean;
    static startTableOrderBy(builder: flatbuffers.Builder): void;
    static addSource(builder: flatbuffers.Builder, source: number): void;
    static addOrderBy(builder: flatbuffers.Builder, orderByOffset: flatbuffers.Offset): void;
    static addUseSource(builder: flatbuffers.Builder, useSource: boolean): void;
    static endTableOrderBy(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): TableOrderByT;
    unpackTo(_o: TableOrderByT): void;
}
export declare class TableOrderByT implements flatbuffers.IGeneratedObject {
    source: number;
    orderBy: OrderByT | null;
    useSource: boolean;
    constructor(source?: number, orderBy?: OrderByT | null, useSource?: boolean);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=table-order-by.d.ts.map