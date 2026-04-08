import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VI16 implements flatbuffers.IUnpackableObject<VI16T> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VI16;
    static getRootAsVI16(bb: flatbuffers.ByteBuffer, obj?: VI16): VI16;
    static getSizePrefixedRootAsVI16(bb: flatbuffers.ByteBuffer, obj?: VI16): VI16;
    v(): number;
    static startVI16(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: number): void;
    static endVI16(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVI16(builder: flatbuffers.Builder, v: number): flatbuffers.Offset;
    unpack(): VI16T;
    unpackTo(_o: VI16T): void;
}
export declare class VI16T implements flatbuffers.IGeneratedObject {
    v: number;
    constructor(v?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vi16.d.ts.map