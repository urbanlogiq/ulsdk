import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class NullableUint implements flatbuffers.IUnpackableObject<NullableUintT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NullableUint;
    static getRootAsNullableUint(bb: flatbuffers.ByteBuffer, obj?: NullableUint): NullableUint;
    static getSizePrefixedRootAsNullableUint(bb: flatbuffers.ByteBuffer, obj?: NullableUint): NullableUint;
    v(): number;
    static startNullableUint(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: number): void;
    static endNullableUint(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createNullableUint(builder: flatbuffers.Builder, v: number): flatbuffers.Offset;
    unpack(): NullableUintT;
    unpackTo(_o: NullableUintT): void;
}
export declare class NullableUintT implements flatbuffers.IGeneratedObject {
    v: number;
    constructor(v?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=nullable-uint.d.ts.map