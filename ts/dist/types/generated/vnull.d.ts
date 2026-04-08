import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VNull implements flatbuffers.IUnpackableObject<VNullT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VNull;
    static getRootAsVNull(bb: flatbuffers.ByteBuffer, obj?: VNull): VNull;
    static getSizePrefixedRootAsVNull(bb: flatbuffers.ByteBuffer, obj?: VNull): VNull;
    static startVNull(builder: flatbuffers.Builder): void;
    static endVNull(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVNull(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): VNullT;
    unpackTo(_o: VNullT): void;
}
export declare class VNullT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vnull.d.ts.map