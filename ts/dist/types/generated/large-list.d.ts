import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * Same as List, but with 64-bit offsets, allowing to represent
 * extremely large data values.
 */
export declare class LargeList implements flatbuffers.IUnpackableObject<LargeListT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): LargeList;
    static getRootAsLargeList(bb: flatbuffers.ByteBuffer, obj?: LargeList): LargeList;
    static getSizePrefixedRootAsLargeList(bb: flatbuffers.ByteBuffer, obj?: LargeList): LargeList;
    static startLargeList(builder: flatbuffers.Builder): void;
    static endLargeList(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createLargeList(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): LargeListT;
    unpackTo(_o: LargeListT): void;
}
export declare class LargeListT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=large-list.d.ts.map