import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * Logically the same as Utf8, but the internal representation uses a view
 * struct that contains the string length and either the string's entire data
 * inline (for small strings) or an inlined prefix, an index of another buffer,
 * and an offset pointing to a slice in that buffer (for non-small strings).
 *
 * Since it uses a variable number of data buffers, each Field with this type
 * must have a corresponding entry in `variadicBufferCounts`.
 */
export declare class Utf8View implements flatbuffers.IUnpackableObject<Utf8ViewT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Utf8View;
    static getRootAsUtf8View(bb: flatbuffers.ByteBuffer, obj?: Utf8View): Utf8View;
    static getSizePrefixedRootAsUtf8View(bb: flatbuffers.ByteBuffer, obj?: Utf8View): Utf8View;
    static startUtf8View(builder: flatbuffers.Builder): void;
    static endUtf8View(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createUtf8View(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): Utf8ViewT;
    unpackTo(_o: Utf8ViewT): void;
}
export declare class Utf8ViewT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=utf8-view.d.ts.map