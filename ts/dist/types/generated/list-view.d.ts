import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * Represents the same logical types that List can, but contains offsets and
 * sizes allowing for writes in any order and sharing of child values among
 * list values.
 */
export declare class ListView implements flatbuffers.IUnpackableObject<ListViewT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ListView;
    static getRootAsListView(bb: flatbuffers.ByteBuffer, obj?: ListView): ListView;
    static getSizePrefixedRootAsListView(bb: flatbuffers.ByteBuffer, obj?: ListView): ListView;
    static startListView(builder: flatbuffers.Builder): void;
    static endListView(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createListView(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): ListViewT;
    unpackTo(_o: ListViewT): void;
}
export declare class ListViewT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=list-view.d.ts.map