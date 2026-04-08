import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class Int implements flatbuffers.IUnpackableObject<IntT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Int;
    static getRootAsInt(bb: flatbuffers.ByteBuffer, obj?: Int): Int;
    static getSizePrefixedRootAsInt(bb: flatbuffers.ByteBuffer, obj?: Int): Int;
    bitWidth(): number;
    isSigned(): boolean;
    static startInt(builder: flatbuffers.Builder): void;
    static addBitWidth(builder: flatbuffers.Builder, bitWidth: number): void;
    static addIsSigned(builder: flatbuffers.Builder, isSigned: boolean): void;
    static endInt(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createInt(builder: flatbuffers.Builder, bitWidth: number, isSigned: boolean): flatbuffers.Offset;
    unpack(): IntT;
    unpackTo(_o: IntT): void;
}
export declare class IntT implements flatbuffers.IGeneratedObject {
    bitWidth: number;
    isSigned: boolean;
    constructor(bitWidth?: number, isSigned?: boolean);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=int.d.ts.map