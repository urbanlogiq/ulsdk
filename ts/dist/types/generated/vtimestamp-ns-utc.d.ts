import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VTimestampNsUtc implements flatbuffers.IUnpackableObject<VTimestampNsUtcT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VTimestampNsUtc;
    static getRootAsVTimestampNsUtc(bb: flatbuffers.ByteBuffer, obj?: VTimestampNsUtc): VTimestampNsUtc;
    static getSizePrefixedRootAsVTimestampNsUtc(bb: flatbuffers.ByteBuffer, obj?: VTimestampNsUtc): VTimestampNsUtc;
    v(): bigint;
    static startVTimestampNsUtc(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: bigint): void;
    static endVTimestampNsUtc(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVTimestampNsUtc(builder: flatbuffers.Builder, v: bigint): flatbuffers.Offset;
    unpack(): VTimestampNsUtcT;
    unpackTo(_o: VTimestampNsUtcT): void;
}
export declare class VTimestampNsUtcT implements flatbuffers.IGeneratedObject {
    v: bigint;
    constructor(v?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vtimestamp-ns-utc.d.ts.map