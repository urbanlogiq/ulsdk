import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class List implements flatbuffers.IUnpackableObject<ListT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): List;
    static getRootAsList(bb: flatbuffers.ByteBuffer, obj?: List): List;
    static getSizePrefixedRootAsList(bb: flatbuffers.ByteBuffer, obj?: List): List;
    static startList(builder: flatbuffers.Builder): void;
    static endList(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createList(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): ListT;
    unpackTo(_o: ListT): void;
}
export declare class ListT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=list.d.ts.map