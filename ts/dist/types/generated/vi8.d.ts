import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VI8 implements flatbuffers.IUnpackableObject<VI8T> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VI8;
    static getRootAsVI8(bb: flatbuffers.ByteBuffer, obj?: VI8): VI8;
    static getSizePrefixedRootAsVI8(bb: flatbuffers.ByteBuffer, obj?: VI8): VI8;
    v(): number;
    static startVI8(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: number): void;
    static endVI8(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVI8(builder: flatbuffers.Builder, v: number): flatbuffers.Offset;
    unpack(): VI8T;
    unpackTo(_o: VI8T): void;
}
export declare class VI8T implements flatbuffers.IGeneratedObject {
    v: number;
    constructor(v?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vi8.d.ts.map