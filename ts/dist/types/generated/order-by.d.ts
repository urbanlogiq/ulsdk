import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { SortOrder } from './sort-order';
import { ValueTransform } from './value-transform';
export declare class OrderBy implements flatbuffers.IUnpackableObject<OrderByT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): OrderBy;
    static getRootAsOrderBy(bb: flatbuffers.ByteBuffer, obj?: OrderBy): OrderBy;
    static getSizePrefixedRootAsOrderBy(bb: flatbuffers.ByteBuffer, obj?: OrderBy): OrderBy;
    sort(): SortOrder;
    field(): string | null;
    field(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    transform(): ValueTransform;
    static startOrderBy(builder: flatbuffers.Builder): void;
    static addSort(builder: flatbuffers.Builder, sort: SortOrder): void;
    static addField(builder: flatbuffers.Builder, fieldOffset: flatbuffers.Offset): void;
    static addTransform(builder: flatbuffers.Builder, transform: ValueTransform): void;
    static endOrderBy(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createOrderBy(builder: flatbuffers.Builder, sort: SortOrder, fieldOffset: flatbuffers.Offset, transform: ValueTransform): flatbuffers.Offset;
    unpack(): OrderByT;
    unpackTo(_o: OrderByT): void;
}
export declare class OrderByT implements flatbuffers.IGeneratedObject {
    sort: SortOrder;
    field: string | Uint8Array | null;
    transform: ValueTransform;
    constructor(sort?: SortOrder, field?: string | Uint8Array | null, transform?: ValueTransform);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=order-by.d.ts.map