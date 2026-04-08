import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VI64 implements flatbuffers.IUnpackableObject<VI64T> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VI64;
    static getRootAsVI64(bb: flatbuffers.ByteBuffer, obj?: VI64): VI64;
    static getSizePrefixedRootAsVI64(bb: flatbuffers.ByteBuffer, obj?: VI64): VI64;
    v(): bigint;
    static startVI64(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: bigint): void;
    static endVI64(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVI64(builder: flatbuffers.Builder, v: bigint): flatbuffers.Offset;
    unpack(): VI64T;
    unpackTo(_o: VI64T): void;
}
export declare class VI64T implements flatbuffers.IGeneratedObject {
    v: bigint;
    constructor(v?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vi64.d.ts.map