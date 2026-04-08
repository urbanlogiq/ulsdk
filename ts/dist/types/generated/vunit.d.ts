import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class VUnit implements flatbuffers.IUnpackableObject<VUnitT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VUnit;
    static getRootAsVUnit(bb: flatbuffers.ByteBuffer, obj?: VUnit): VUnit;
    static getSizePrefixedRootAsVUnit(bb: flatbuffers.ByteBuffer, obj?: VUnit): VUnit;
    static startVUnit(builder: flatbuffers.Builder): void;
    static endVUnit(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVUnit(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): VUnitT;
    unpackTo(_o: VUnitT): void;
}
export declare class VUnitT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vunit.d.ts.map