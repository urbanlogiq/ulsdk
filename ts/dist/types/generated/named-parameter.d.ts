import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Schema, SchemaT } from './schema';
export declare class NamedParameter implements flatbuffers.IUnpackableObject<NamedParameterT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NamedParameter;
    static getRootAsNamedParameter(bb: flatbuffers.ByteBuffer, obj?: NamedParameter): NamedParameter;
    static getSizePrefixedRootAsNamedParameter(bb: flatbuffers.ByteBuffer, obj?: NamedParameter): NamedParameter;
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    schema(obj?: Schema): Schema | null;
    flags(): number;
    description(): string | null;
    description(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startNamedParameter(builder: flatbuffers.Builder): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static addSchema(builder: flatbuffers.Builder, schemaOffset: flatbuffers.Offset): void;
    static addFlags(builder: flatbuffers.Builder, flags: number): void;
    static addDescription(builder: flatbuffers.Builder, descriptionOffset: flatbuffers.Offset): void;
    static endNamedParameter(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): NamedParameterT;
    unpackTo(_o: NamedParameterT): void;
}
export declare class NamedParameterT implements flatbuffers.IGeneratedObject {
    name: string | Uint8Array | null;
    schema: SchemaT | null;
    flags: number;
    description: string | Uint8Array | null;
    constructor(name?: string | Uint8Array | null, schema?: SchemaT | null, flags?: number, description?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=named-parameter.d.ts.map