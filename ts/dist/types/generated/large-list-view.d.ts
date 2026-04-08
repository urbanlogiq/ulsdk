import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * Same as ListView, but with 64-bit offsets and sizes, allowing to represent
 * extremely large data values.
 */
export declare class LargeListView implements flatbuffers.IUnpackableObject<LargeListViewT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): LargeListView;
    static getRootAsLargeListView(bb: flatbuffers.ByteBuffer, obj?: LargeListView): LargeListView;
    static getSizePrefixedRootAsLargeListView(bb: flatbuffers.ByteBuffer, obj?: LargeListView): LargeListView;
    static startLargeListView(builder: flatbuffers.Builder): void;
    static endLargeListView(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createLargeListView(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): LargeListViewT;
    unpackTo(_o: LargeListViewT): void;
}
export declare class LargeListViewT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=large-list-view.d.ts.map