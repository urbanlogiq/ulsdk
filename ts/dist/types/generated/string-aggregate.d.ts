import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class StringAggregate implements flatbuffers.IUnpackableObject<StringAggregateT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): StringAggregate;
    static getRootAsStringAggregate(bb: flatbuffers.ByteBuffer, obj?: StringAggregate): StringAggregate;
    static getSizePrefixedRootAsStringAggregate(bb: flatbuffers.ByteBuffer, obj?: StringAggregate): StringAggregate;
    str(): string | null;
    str(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    count(): bigint;
    static startStringAggregate(builder: flatbuffers.Builder): void;
    static addStr(builder: flatbuffers.Builder, strOffset: flatbuffers.Offset): void;
    static addCount(builder: flatbuffers.Builder, count: bigint): void;
    static endStringAggregate(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createStringAggregate(builder: flatbuffers.Builder, strOffset: flatbuffers.Offset, count: bigint): flatbuffers.Offset;
    unpack(): StringAggregateT;
    unpackTo(_o: StringAggregateT): void;
}
export declare class StringAggregateT implements flatbuffers.IGeneratedObject {
    str: string | Uint8Array | null;
    count: bigint;
    constructor(str?: string | Uint8Array | null, count?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=string-aggregate.d.ts.map