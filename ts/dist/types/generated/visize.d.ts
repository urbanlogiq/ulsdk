import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VIsize implements flatbuffers.IUnpackableObject<VIsizeT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VIsize;
    static getRootAsVIsize(bb: flatbuffers.ByteBuffer, obj?: VIsize): VIsize;
    static getSizePrefixedRootAsVIsize(bb: flatbuffers.ByteBuffer, obj?: VIsize): VIsize;
    v(): bigint;
    static startVIsize(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: bigint): void;
    static endVIsize(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVIsize(builder: flatbuffers.Builder, v: bigint): flatbuffers.Offset;
    unpack(): VIsizeT;
    unpackTo(_o: VIsizeT): void;
}
export declare class VIsizeT implements flatbuffers.IGeneratedObject {
    v: bigint;
    constructor(v?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=visize.d.ts.map