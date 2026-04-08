import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * Append rows to a table. The `content` field is Arrow IPC Stream formatted.
 */
export declare class Append implements flatbuffers.IUnpackableObject<AppendT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Append;
    static getRootAsAppend(bb: flatbuffers.ByteBuffer, obj?: Append): Append;
    static getSizePrefixedRootAsAppend(bb: flatbuffers.ByteBuffer, obj?: Append): Append;
    /**
     * The row content to append in Arrow IPC Stream format.
     */
    content(index: number): number | null;
    contentLength(): number;
    contentArray(): Uint8Array | null;
    static startAppend(builder: flatbuffers.Builder): void;
    static addContent(builder: flatbuffers.Builder, contentOffset: flatbuffers.Offset): void;
    static createContentVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startContentVector(builder: flatbuffers.Builder, numElems: number): void;
    static endAppend(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createAppend(builder: flatbuffers.Builder, contentOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): AppendT;
    unpackTo(_o: AppendT): void;
}
export declare class AppendT implements flatbuffers.IGeneratedObject {
    content: (number)[];
    constructor(content?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=append.d.ts.map