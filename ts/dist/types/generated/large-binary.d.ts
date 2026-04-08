import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * Same as Binary, but with 64-bit offsets, allowing to represent
 * extremely large data values.
 */
export declare class LargeBinary implements flatbuffers.IUnpackableObject<LargeBinaryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): LargeBinary;
    static getRootAsLargeBinary(bb: flatbuffers.ByteBuffer, obj?: LargeBinary): LargeBinary;
    static getSizePrefixedRootAsLargeBinary(bb: flatbuffers.ByteBuffer, obj?: LargeBinary): LargeBinary;
    static startLargeBinary(builder: flatbuffers.Builder): void;
    static endLargeBinary(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createLargeBinary(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): LargeBinaryT;
    unpackTo(_o: LargeBinaryT): void;
}
export declare class LargeBinaryT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=large-binary.d.ts.map