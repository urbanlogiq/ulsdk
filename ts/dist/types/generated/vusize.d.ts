import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VUsize implements flatbuffers.IUnpackableObject<VUsizeT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VUsize;
    static getRootAsVUsize(bb: flatbuffers.ByteBuffer, obj?: VUsize): VUsize;
    static getSizePrefixedRootAsVUsize(bb: flatbuffers.ByteBuffer, obj?: VUsize): VUsize;
    v(): bigint;
    static startVUsize(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: bigint): void;
    static endVUsize(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVUsize(builder: flatbuffers.Builder, v: bigint): flatbuffers.Offset;
    unpack(): VUsizeT;
    unpackTo(_o: VUsizeT): void;
}
export declare class VUsizeT implements flatbuffers.IGeneratedObject {
    v: bigint;
    constructor(v?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vusize.d.ts.map