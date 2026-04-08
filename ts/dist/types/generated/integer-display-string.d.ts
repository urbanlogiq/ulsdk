import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class IntegerDisplayString implements flatbuffers.IUnpackableObject<IntegerDisplayStringT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): IntegerDisplayString;
    static getRootAsIntegerDisplayString(bb: flatbuffers.ByteBuffer, obj?: IntegerDisplayString): IntegerDisplayString;
    static getSizePrefixedRootAsIntegerDisplayString(bb: flatbuffers.ByteBuffer, obj?: IntegerDisplayString): IntegerDisplayString;
    value(): bigint;
    displayName(): string | null;
    displayName(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startIntegerDisplayString(builder: flatbuffers.Builder): void;
    static addValue(builder: flatbuffers.Builder, value: bigint): void;
    static addDisplayName(builder: flatbuffers.Builder, displayNameOffset: flatbuffers.Offset): void;
    static endIntegerDisplayString(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createIntegerDisplayString(builder: flatbuffers.Builder, value: bigint, displayNameOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): IntegerDisplayStringT;
    unpackTo(_o: IntegerDisplayStringT): void;
}
export declare class IntegerDisplayStringT implements flatbuffers.IGeneratedObject {
    value: bigint;
    displayName: string | Uint8Array | null;
    constructor(value?: bigint, displayName?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=integer-display-string.d.ts.map