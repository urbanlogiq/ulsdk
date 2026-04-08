import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class ListDirectory implements flatbuffers.IUnpackableObject<ListDirectoryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ListDirectory;
    static getRootAsListDirectory(bb: flatbuffers.ByteBuffer, obj?: ListDirectory): ListDirectory;
    static getSizePrefixedRootAsListDirectory(bb: flatbuffers.ByteBuffer, obj?: ListDirectory): ListDirectory;
    static startListDirectory(builder: flatbuffers.Builder): void;
    static endListDirectory(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createListDirectory(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): ListDirectoryT;
    unpackTo(_o: ListDirectoryT): void;
}
export declare class ListDirectoryT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=list-directory.d.ts.map