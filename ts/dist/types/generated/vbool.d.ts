import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VBool implements flatbuffers.IUnpackableObject<VBoolT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VBool;
    static getRootAsVBool(bb: flatbuffers.ByteBuffer, obj?: VBool): VBool;
    static getSizePrefixedRootAsVBool(bb: flatbuffers.ByteBuffer, obj?: VBool): VBool;
    v(): boolean;
    static startVBool(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, v: boolean): void;
    static endVBool(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVBool(builder: flatbuffers.Builder, v: boolean): flatbuffers.Offset;
    unpack(): VBoolT;
    unpackTo(_o: VBoolT): void;
}
export declare class VBoolT implements flatbuffers.IGeneratedObject {
    v: boolean;
    constructor(v?: boolean);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vbool.d.ts.map