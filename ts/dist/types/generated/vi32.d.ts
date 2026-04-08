import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VI32 implements flatbuffers.IUnpackableObject<VI32T> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VI32;
    static getRootAsVI32(bb: flatbuffers.ByteBuffer, obj?: VI32): VI32;
    static getSizePrefixedRootAsVI32(bb: flatbuffers.ByteBuffer, obj?: VI32): VI32;
    v(): number;
    static startVI32(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: number): void;
    static endVI32(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVI32(builder: flatbuffers.Builder, v: number): flatbuffers.Offset;
    unpack(): VI32T;
    unpackTo(_o: VI32T): void;
}
export declare class VI32T implements flatbuffers.IGeneratedObject {
    v: number;
    constructor(v?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vi32.d.ts.map