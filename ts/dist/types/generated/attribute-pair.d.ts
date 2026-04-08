import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class AttributePair implements flatbuffers.IUnpackableObject<AttributePairT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): AttributePair;
    static getRootAsAttributePair(bb: flatbuffers.ByteBuffer, obj?: AttributePair): AttributePair;
    static getSizePrefixedRootAsAttributePair(bb: flatbuffers.ByteBuffer, obj?: AttributePair): AttributePair;
    key(): string | null;
    key(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    value(): string | null;
    value(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startAttributePair(builder: flatbuffers.Builder): void;
    static addKey(builder: flatbuffers.Builder, keyOffset: flatbuffers.Offset): void;
    static addValue(builder: flatbuffers.Builder, valueOffset: flatbuffers.Offset): void;
    static endAttributePair(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createAttributePair(builder: flatbuffers.Builder, keyOffset: flatbuffers.Offset, valueOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): AttributePairT;
    unpackTo(_o: AttributePairT): void;
}
export declare class AttributePairT implements flatbuffers.IGeneratedObject {
    key: string | Uint8Array | null;
    value: string | Uint8Array | null;
    constructor(key?: string | Uint8Array | null, value?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=attribute-pair.d.ts.map