import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class Bool implements flatbuffers.IUnpackableObject<BoolT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Bool;
    static getRootAsBool(bb: flatbuffers.ByteBuffer, obj?: Bool): Bool;
    static getSizePrefixedRootAsBool(bb: flatbuffers.ByteBuffer, obj?: Bool): Bool;
    static startBool(builder: flatbuffers.Builder): void;
    static endBool(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createBool(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): BoolT;
    unpackTo(_o: BoolT): void;
}
export declare class BoolT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=bool.d.ts.map