import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Document, DocumentT } from './document';
export declare class Documents implements flatbuffers.IUnpackableObject<DocumentsT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Documents;
    static getRootAsDocuments(bb: flatbuffers.ByteBuffer, obj?: Documents): Documents;
    static getSizePrefixedRootAsDocuments(bb: flatbuffers.ByteBuffer, obj?: Documents): Documents;
    documents(index: number, obj?: Document): Document | null;
    documentsLength(): number;
    static startDocuments(builder: flatbuffers.Builder): void;
    static addDocuments(builder: flatbuffers.Builder, documentsOffset: flatbuffers.Offset): void;
    static createDocumentsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startDocumentsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endDocuments(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDocuments(builder: flatbuffers.Builder, documentsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DocumentsT;
    unpackTo(_o: DocumentsT): void;
}
export declare class DocumentsT implements flatbuffers.IGeneratedObject {
    documents: (DocumentT)[];
    constructor(documents?: (DocumentT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=documents.d.ts.map