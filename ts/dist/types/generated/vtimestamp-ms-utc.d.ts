import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VTimestampMsUtc implements flatbuffers.IUnpackableObject<VTimestampMsUtcT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VTimestampMsUtc;
    static getRootAsVTimestampMsUtc(bb: flatbuffers.ByteBuffer, obj?: VTimestampMsUtc): VTimestampMsUtc;
    static getSizePrefixedRootAsVTimestampMsUtc(bb: flatbuffers.ByteBuffer, obj?: VTimestampMsUtc): VTimestampMsUtc;
    v(): bigint;
    static startVTimestampMsUtc(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: bigint): void;
    static endVTimestampMsUtc(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVTimestampMsUtc(builder: flatbuffers.Builder, v: bigint): flatbuffers.Offset;
    unpack(): VTimestampMsUtcT;
    unpackTo(_o: VTimestampMsUtcT): void;
}
export declare class VTimestampMsUtcT implements flatbuffers.IGeneratedObject {
    v: bigint;
    constructor(v?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vtimestamp-ms-utc.d.ts.map