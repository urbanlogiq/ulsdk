import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VTimestampNs implements flatbuffers.IUnpackableObject<VTimestampNsT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VTimestampNs;
    static getRootAsVTimestampNs(bb: flatbuffers.ByteBuffer, obj?: VTimestampNs): VTimestampNs;
    static getSizePrefixedRootAsVTimestampNs(bb: flatbuffers.ByteBuffer, obj?: VTimestampNs): VTimestampNs;
    v(): bigint;
    static startVTimestampNs(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: bigint): void;
    static endVTimestampNs(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVTimestampNs(builder: flatbuffers.Builder, v: bigint): flatbuffers.Offset;
    unpack(): VTimestampNsT;
    unpackTo(_o: VTimestampNsT): void;
}
export declare class VTimestampNsT implements flatbuffers.IGeneratedObject {
    v: bigint;
    constructor(v?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vtimestamp-ns.d.ts.map