import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class ValueName implements flatbuffers.IUnpackableObject<ValueNameT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ValueName;
    static getRootAsValueName(bb: flatbuffers.ByteBuffer, obj?: ValueName): ValueName;
    static getSizePrefixedRootAsValueName(bb: flatbuffers.ByteBuffer, obj?: ValueName): ValueName;
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startValueName(builder: flatbuffers.Builder): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static endValueName(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createValueName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ValueNameT;
    unpackTo(_o: ValueNameT): void;
}
export declare class ValueNameT implements flatbuffers.IGeneratedObject {
    name: string | Uint8Array | null;
    constructor(name?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=value-name.d.ts.map