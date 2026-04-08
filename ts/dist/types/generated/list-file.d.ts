import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class ListFile implements flatbuffers.IUnpackableObject<ListFileT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ListFile;
    static getRootAsListFile(bb: flatbuffers.ByteBuffer, obj?: ListFile): ListFile;
    static getSizePrefixedRootAsListFile(bb: flatbuffers.ByteBuffer, obj?: ListFile): ListFile;
    mime(): string | null;
    mime(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    virus(): string | null;
    virus(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    size(): bigint;
    static startListFile(builder: flatbuffers.Builder): void;
    static addMime(builder: flatbuffers.Builder, mimeOffset: flatbuffers.Offset): void;
    static addVirus(builder: flatbuffers.Builder, virusOffset: flatbuffers.Offset): void;
    static addSize(builder: flatbuffers.Builder, size: bigint): void;
    static endListFile(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createListFile(builder: flatbuffers.Builder, mimeOffset: flatbuffers.Offset, virusOffset: flatbuffers.Offset, size: bigint): flatbuffers.Offset;
    unpack(): ListFileT;
    unpackTo(_o: ListFileT): void;
}
export declare class ListFileT implements flatbuffers.IGeneratedObject {
    mime: string | Uint8Array | null;
    virus: string | Uint8Array | null;
    size: bigint;
    constructor(mime?: string | Uint8Array | null, virus?: string | Uint8Array | null, size?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=list-file.d.ts.map