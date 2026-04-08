import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VStr implements flatbuffers.IUnpackableObject<VStrT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VStr;
    static getRootAsVStr(bb: flatbuffers.ByteBuffer, obj?: VStr): VStr;
    static getSizePrefixedRootAsVStr(bb: flatbuffers.ByteBuffer, obj?: VStr): VStr;
    v(): string | null;
    v(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startVStr(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, vOffset: flatbuffers.Offset): void;
    static endVStr(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVStr(builder: flatbuffers.Builder, vOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): VStrT;
    unpackTo(_o: VStrT): void;
}
export declare class VStrT implements flatbuffers.IGeneratedObject {
    v: string | Uint8Array | null;
    constructor(v?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vstr.d.ts.map