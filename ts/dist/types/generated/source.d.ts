import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ContentId, ContentIdT } from './content-id';
import { NamedParameter, NamedParameterT } from './named-parameter';
import { ObjectId, ObjectIdT } from './object-id';
import { Schema, SchemaT } from './schema';
export declare class Source implements flatbuffers.IUnpackableObject<SourceT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Source;
    static getRootAsSource(bb: flatbuffers.ByteBuffer, obj?: Source): Source;
    static getSizePrefixedRootAsSource(bb: flatbuffers.ByteBuffer, obj?: Source): Source;
    url(): string | null;
    url(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    options(index: number): number | null;
    optionsLength(): number;
    optionsArray(): Uint8Array | null;
    schemas(index: number, obj?: Schema): Schema | null;
    schemasLength(): number;
    metadata(obj?: ObjectId): ObjectId | null;
    metadataRevision(obj?: ContentId): ContentId | null;
    namedParameters(index: number, obj?: NamedParameter): NamedParameter | null;
    namedParametersLength(): number;
    static startSource(builder: flatbuffers.Builder): void;
    static addUrl(builder: flatbuffers.Builder, urlOffset: flatbuffers.Offset): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static addOptions(builder: flatbuffers.Builder, optionsOffset: flatbuffers.Offset): void;
    static createOptionsVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startOptionsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addSchemas(builder: flatbuffers.Builder, schemasOffset: flatbuffers.Offset): void;
    static createSchemasVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startSchemasVector(builder: flatbuffers.Builder, numElems: number): void;
    static addMetadata(builder: flatbuffers.Builder, metadataOffset: flatbuffers.Offset): void;
    static addMetadataRevision(builder: flatbuffers.Builder, metadataRevisionOffset: flatbuffers.Offset): void;
    static addNamedParameters(builder: flatbuffers.Builder, namedParametersOffset: flatbuffers.Offset): void;
    static createNamedParametersVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startNamedParametersVector(builder: flatbuffers.Builder, numElems: number): void;
    static endSource(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): SourceT;
    unpackTo(_o: SourceT): void;
}
export declare class SourceT implements flatbuffers.IGeneratedObject {
    url: string | Uint8Array | null;
    name: string | Uint8Array | null;
    options: (number)[];
    schemas: (SchemaT)[];
    metadata: ObjectIdT | null;
    metadataRevision: ContentIdT | null;
    namedParameters: (NamedParameterT)[];
    constructor(url?: string | Uint8Array | null, name?: string | Uint8Array | null, options?: (number)[], schemas?: (SchemaT)[], metadata?: ObjectIdT | null, metadataRevision?: ContentIdT | null, namedParameters?: (NamedParameterT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=source.d.ts.map