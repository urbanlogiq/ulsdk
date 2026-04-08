import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * These are stored in the flatbuffer in the Type union below
 */
export declare class Null implements flatbuffers.IUnpackableObject<NullT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Null;
    static getRootAsNull(bb: flatbuffers.ByteBuffer, obj?: Null): Null;
    static getSizePrefixedRootAsNull(bb: flatbuffers.ByteBuffer, obj?: Null): Null;
    static startNull(builder: flatbuffers.Builder): void;
    static endNull(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createNull(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): NullT;
    unpackTo(_o: NullT): void;
}
export declare class NullT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=null.d.ts.map