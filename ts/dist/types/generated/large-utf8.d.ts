import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * Same as Utf8, but with 64-bit offsets, allowing to represent
 * extremely large data values.
 */
export declare class LargeUtf8 implements flatbuffers.IUnpackableObject<LargeUtf8T> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): LargeUtf8;
    static getRootAsLargeUtf8(bb: flatbuffers.ByteBuffer, obj?: LargeUtf8): LargeUtf8;
    static getSizePrefixedRootAsLargeUtf8(bb: flatbuffers.ByteBuffer, obj?: LargeUtf8): LargeUtf8;
    static startLargeUtf8(builder: flatbuffers.Builder): void;
    static endLargeUtf8(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createLargeUtf8(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): LargeUtf8T;
    unpackTo(_o: LargeUtf8T): void;
}
export declare class LargeUtf8T implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=large-utf8.d.ts.map