import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ContentId, ContentIdT } from './content-id';
import { ObjectId, ObjectIdT } from './object-id';
import { Schema, SchemaT } from './schema';
/**
 * A Stream is an instance of a source. The main difference is the parameters
 * field is not a ParameterDesc descriptor object but the actual, serialized
 * parameter values.
 *
 * Code performing the operation on the source will be able to construct a
 * stream object from this description and downstream code will be able to
 * read from it.
 */
export declare class Stream implements flatbuffers.IUnpackableObject<StreamT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Stream;
    static getRootAsStream(bb: flatbuffers.ByteBuffer, obj?: Stream): Stream;
    static getSizePrefixedRootAsStream(bb: flatbuffers.ByteBuffer, obj?: Stream): Stream;
    url(): string | null;
    url(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    options(index: number): number | null;
    optionsLength(): number;
    optionsArray(): Uint8Array | null;
    parameters(index: number): number | null;
    parametersLength(): number;
    parametersArray(): Uint8Array | null;
    schema(obj?: Schema): Schema | null;
    metadata(obj?: ObjectId): ObjectId | null;
    metadataRevision(obj?: ContentId): ContentId | null;
    flags(): number;
    substreams(index: number, obj?: ObjectId): ObjectId | null;
    substreamsLength(): number;
    static startStream(builder: flatbuffers.Builder): void;
    static addUrl(builder: flatbuffers.Builder, urlOffset: flatbuffers.Offset): void;
    static addOptions(builder: flatbuffers.Builder, optionsOffset: flatbuffers.Offset): void;
    static createOptionsVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startOptionsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addParameters(builder: flatbuffers.Builder, parametersOffset: flatbuffers.Offset): void;
    static createParametersVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startParametersVector(builder: flatbuffers.Builder, numElems: number): void;
    static addSchema(builder: flatbuffers.Builder, schemaOffset: flatbuffers.Offset): void;
    static addMetadata(builder: flatbuffers.Builder, metadataOffset: flatbuffers.Offset): void;
    static addMetadataRevision(builder: flatbuffers.Builder, metadataRevisionOffset: flatbuffers.Offset): void;
    static addFlags(builder: flatbuffers.Builder, flags: number): void;
    static addSubstreams(builder: flatbuffers.Builder, substreamsOffset: flatbuffers.Offset): void;
    static createSubstreamsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startSubstreamsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endStream(builder: flatbuffers.Builder): flatbuffers.Offset;
    static finishStreamBuffer(builder: flatbuffers.Builder, offset: flatbuffers.Offset): void;
    static finishSizePrefixedStreamBuffer(builder: flatbuffers.Builder, offset: flatbuffers.Offset): void;
    unpack(): StreamT;
    unpackTo(_o: StreamT): void;
}
export declare class StreamT implements flatbuffers.IGeneratedObject {
    url: string | Uint8Array | null;
    options: (number)[];
    parameters: (number)[];
    schema: SchemaT | null;
    metadata: ObjectIdT | null;
    metadataRevision: ContentIdT | null;
    flags: number;
    substreams: (ObjectIdT)[];
    constructor(url?: string | Uint8Array | null, options?: (number)[], parameters?: (number)[], schema?: SchemaT | null, metadata?: ObjectIdT | null, metadataRevision?: ContentIdT | null, flags?: number, substreams?: (ObjectIdT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=stream.d.ts.map