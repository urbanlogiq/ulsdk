import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * Opaque binary data
 */
export declare class Binary implements flatbuffers.IUnpackableObject<BinaryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Binary;
    static getRootAsBinary(bb: flatbuffers.ByteBuffer, obj?: Binary): Binary;
    static getSizePrefixedRootAsBinary(bb: flatbuffers.ByteBuffer, obj?: Binary): Binary;
    static startBinary(builder: flatbuffers.Builder): void;
    static endBinary(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createBinary(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): BinaryT;
    unpackTo(_o: BinaryT): void;
}
export declare class BinaryT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=binary.d.ts.map