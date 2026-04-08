import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VTimestampMs implements flatbuffers.IUnpackableObject<VTimestampMsT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VTimestampMs;
    static getRootAsVTimestampMs(bb: flatbuffers.ByteBuffer, obj?: VTimestampMs): VTimestampMs;
    static getSizePrefixedRootAsVTimestampMs(bb: flatbuffers.ByteBuffer, obj?: VTimestampMs): VTimestampMs;
    v(): bigint;
    static startVTimestampMs(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: bigint): void;
    static endVTimestampMs(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVTimestampMs(builder: flatbuffers.Builder, v: bigint): flatbuffers.Offset;
    unpack(): VTimestampMsT;
    unpackTo(_o: VTimestampMsT): void;
}
export declare class VTimestampMsT implements flatbuffers.IGeneratedObject {
    v: bigint;
    constructor(v?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vtimestamp-ms.d.ts.map