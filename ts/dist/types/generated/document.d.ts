import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class Document implements flatbuffers.IUnpackableObject<DocumentT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Document;
    static getRootAsDocument(bb: flatbuffers.ByteBuffer, obj?: Document): Document;
    static getSizePrefixedRootAsDocument(bb: flatbuffers.ByteBuffer, obj?: Document): Document;
    filename(): string | null;
    filename(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    url(): string | null;
    url(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    mimeType(): string | null;
    mimeType(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    displayName(): string | null;
    displayName(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startDocument(builder: flatbuffers.Builder): void;
    static addFilename(builder: flatbuffers.Builder, filenameOffset: flatbuffers.Offset): void;
    static addUrl(builder: flatbuffers.Builder, urlOffset: flatbuffers.Offset): void;
    static addMimeType(builder: flatbuffers.Builder, mimeTypeOffset: flatbuffers.Offset): void;
    static addDisplayName(builder: flatbuffers.Builder, displayNameOffset: flatbuffers.Offset): void;
    static endDocument(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDocument(builder: flatbuffers.Builder, filenameOffset: flatbuffers.Offset, urlOffset: flatbuffers.Offset, mimeTypeOffset: flatbuffers.Offset, displayNameOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DocumentT;
    unpackTo(_o: DocumentT): void;
}
export declare class DocumentT implements flatbuffers.IGeneratedObject {
    filename: string | Uint8Array | null;
    url: string | Uint8Array | null;
    mimeType: string | Uint8Array | null;
    displayName: string | Uint8Array | null;
    constructor(filename?: string | Uint8Array | null, url?: string | Uint8Array | null, mimeType?: string | Uint8Array | null, displayName?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=document.d.ts.map