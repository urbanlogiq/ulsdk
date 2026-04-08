import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class FixedSizeList implements flatbuffers.IUnpackableObject<FixedSizeListT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): FixedSizeList;
    static getRootAsFixedSizeList(bb: flatbuffers.ByteBuffer, obj?: FixedSizeList): FixedSizeList;
    static getSizePrefixedRootAsFixedSizeList(bb: flatbuffers.ByteBuffer, obj?: FixedSizeList): FixedSizeList;
    /**
     * Number of list items per value
     */
    listSize(): number;
    static startFixedSizeList(builder: flatbuffers.Builder): void;
    static addListSize(builder: flatbuffers.Builder, listSize: number): void;
    static endFixedSizeList(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createFixedSizeList(builder: flatbuffers.Builder, listSize: number): flatbuffers.Offset;
    unpack(): FixedSizeListT;
    unpackTo(_o: FixedSizeListT): void;
}
export declare class FixedSizeListT implements flatbuffers.IGeneratedObject {
    listSize: number;
    constructor(listSize?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=fixed-size-list.d.ts.map