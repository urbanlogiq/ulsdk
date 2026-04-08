import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Endianness } from './endianness';
import { Field, FieldT } from './field';
import { KeyValue, KeyValueT } from './key-value';
/**
 * ----------------------------------------------------------------------
 * A Schema describes the columns in a row batch
 */
export declare class Schema implements flatbuffers.IUnpackableObject<SchemaT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Schema;
    static getRootAsSchema(bb: flatbuffers.ByteBuffer, obj?: Schema): Schema;
    static getSizePrefixedRootAsSchema(bb: flatbuffers.ByteBuffer, obj?: Schema): Schema;
    /**
     * endianness of the buffer
     * it is Little Endian by default
     * if endianness doesn't match the underlying system then the vectors need to be converted
     */
    endianness(): Endianness;
    fields(index: number, obj?: Field): Field | null;
    fieldsLength(): number;
    customMetadata(index: number, obj?: KeyValue): KeyValue | null;
    customMetadataLength(): number;
    /**
     * Features used in the stream/file.
     */
    features(index: number): bigint | null;
    featuresLength(): number;
    static startSchema(builder: flatbuffers.Builder): void;
    static addEndianness(builder: flatbuffers.Builder, endianness: Endianness): void;
    static addFields(builder: flatbuffers.Builder, fieldsOffset: flatbuffers.Offset): void;
    static createFieldsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startFieldsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addCustomMetadata(builder: flatbuffers.Builder, customMetadataOffset: flatbuffers.Offset): void;
    static createCustomMetadataVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startCustomMetadataVector(builder: flatbuffers.Builder, numElems: number): void;
    static addFeatures(builder: flatbuffers.Builder, featuresOffset: flatbuffers.Offset): void;
    static createFeaturesVector(builder: flatbuffers.Builder, data: bigint[]): flatbuffers.Offset;
    static startFeaturesVector(builder: flatbuffers.Builder, numElems: number): void;
    static endSchema(builder: flatbuffers.Builder): flatbuffers.Offset;
    static finishSchemaBuffer(builder: flatbuffers.Builder, offset: flatbuffers.Offset): void;
    static finishSizePrefixedSchemaBuffer(builder: flatbuffers.Builder, offset: flatbuffers.Offset): void;
    static createSchema(builder: flatbuffers.Builder, endianness: Endianness, fieldsOffset: flatbuffers.Offset, customMetadataOffset: flatbuffers.Offset, featuresOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): SchemaT;
    unpackTo(_o: SchemaT): void;
}
export declare class SchemaT implements flatbuffers.IGeneratedObject {
    endianness: Endianness;
    fields: (FieldT)[];
    customMetadata: (KeyValueT)[];
    features: (bigint)[];
    constructor(endianness?: Endianness, fields?: (FieldT)[], customMetadata?: (KeyValueT)[], features?: (bigint)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=schema.d.ts.map