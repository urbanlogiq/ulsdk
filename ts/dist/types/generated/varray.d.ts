import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ValueInstance, ValueInstanceT } from './value-instance';
export declare class VArray implements flatbuffers.IUnpackableObject<VArrayT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VArray;
    static getRootAsVArray(bb: flatbuffers.ByteBuffer, obj?: VArray): VArray;
    static getSizePrefixedRootAsVArray(bb: flatbuffers.ByteBuffer, obj?: VArray): VArray;
    v(index: number, obj?: ValueInstance): ValueInstance | null;
    vLength(): number;
    static startVArray(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, vOffset: flatbuffers.Offset): void;
    static createVVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startVVector(builder: flatbuffers.Builder, numElems: number): void;
    static endVArray(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVArray(builder: flatbuffers.Builder, vOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): VArrayT;
    unpackTo(_o: VArrayT): void;
}
export declare class VArrayT implements flatbuffers.IGeneratedObject {
    v: (ValueInstanceT)[];
    constructor(v?: (ValueInstanceT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=varray.d.ts.map