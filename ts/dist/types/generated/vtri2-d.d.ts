import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Tri2D, Tri2DT } from './tri2-d';
export declare class VTri2D implements flatbuffers.IUnpackableObject<VTri2DT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VTri2D;
    static getRootAsVTri2D(bb: flatbuffers.ByteBuffer, obj?: VTri2D): VTri2D;
    static getSizePrefixedRootAsVTri2D(bb: flatbuffers.ByteBuffer, obj?: VTri2D): VTri2D;
    v(obj?: Tri2D): Tri2D | null;
    static startVTri2D(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, vOffset: flatbuffers.Offset): void;
    static endVTri2D(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVTri2D(builder: flatbuffers.Builder, vOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): VTri2DT;
    unpackTo(_o: VTri2DT): void;
}
export declare class VTri2DT implements flatbuffers.IGeneratedObject {
    v: Tri2DT | null;
    constructor(v?: Tri2DT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vtri2-d.d.ts.map