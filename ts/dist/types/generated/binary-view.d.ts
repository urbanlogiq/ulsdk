import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * Logically the same as Binary, but the internal representation uses a view
 * struct that contains the string length and either the string's entire data
 * inline (for small strings) or an inlined prefix, an index of another buffer,
 * and an offset pointing to a slice in that buffer (for non-small strings).
 *
 * Since it uses a variable number of data buffers, each Field with this type
 * must have a corresponding entry in `variadicBufferCounts`.
 */
export declare class BinaryView implements flatbuffers.IUnpackableObject<BinaryViewT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): BinaryView;
    static getRootAsBinaryView(bb: flatbuffers.ByteBuffer, obj?: BinaryView): BinaryView;
    static getSizePrefixedRootAsBinaryView(bb: flatbuffers.ByteBuffer, obj?: BinaryView): BinaryView;
    static startBinaryView(builder: flatbuffers.Builder): void;
    static endBinaryView(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createBinaryView(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): BinaryViewT;
    unpackTo(_o: BinaryViewT): void;
}
export declare class BinaryViewT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=binary-view.d.ts.map