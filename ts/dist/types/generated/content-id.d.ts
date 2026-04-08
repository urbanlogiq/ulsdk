import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class ContentId implements flatbuffers.IUnpackableObject<ContentIdT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ContentId;
    static getRootAsContentId(bb: flatbuffers.ByteBuffer, obj?: ContentId): ContentId;
    static getSizePrefixedRootAsContentId(bb: flatbuffers.ByteBuffer, obj?: ContentId): ContentId;
    b(index: number): number | null;
    bLength(): number;
    bArray(): Uint8Array | null;
    static startContentId(builder: flatbuffers.Builder): void;
    static addB(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): void;
    static createBVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startBVector(builder: flatbuffers.Builder, numElems: number): void;
    static endContentId(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createContentId(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ContentIdT;
    unpackTo(_o: ContentIdT): void;
}
export declare class ContentIdT implements flatbuffers.IGeneratedObject {
    b: (number)[];
    constructor(b?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=content-id.d.ts.map