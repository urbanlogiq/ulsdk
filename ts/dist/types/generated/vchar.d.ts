import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VChar implements flatbuffers.IUnpackableObject<VCharT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VChar;
    static getRootAsVChar(bb: flatbuffers.ByteBuffer, obj?: VChar): VChar;
    static getSizePrefixedRootAsVChar(bb: flatbuffers.ByteBuffer, obj?: VChar): VChar;
    v(): number;
    static startVChar(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: number): void;
    static endVChar(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVChar(builder: flatbuffers.Builder, v: number): flatbuffers.Offset;
    unpack(): VCharT;
    unpackTo(_o: VCharT): void;
}
export declare class VCharT implements flatbuffers.IGeneratedObject {
    v: number;
    constructor(v?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vchar.d.ts.map