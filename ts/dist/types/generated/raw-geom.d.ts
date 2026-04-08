import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class RawGeom implements flatbuffers.IUnpackableObject<RawGeomT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): RawGeom;
    static getRootAsRawGeom(bb: flatbuffers.ByteBuffer, obj?: RawGeom): RawGeom;
    static getSizePrefixedRootAsRawGeom(bb: flatbuffers.ByteBuffer, obj?: RawGeom): RawGeom;
    geom(index: number): number | null;
    geomLength(): number;
    geomArray(): Uint8Array | null;
    static startRawGeom(builder: flatbuffers.Builder): void;
    static addGeom(builder: flatbuffers.Builder, geomOffset: flatbuffers.Offset): void;
    static createGeomVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startGeomVector(builder: flatbuffers.Builder, numElems: number): void;
    static endRawGeom(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createRawGeom(builder: flatbuffers.Builder, geomOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): RawGeomT;
    unpackTo(_o: RawGeomT): void;
}
export declare class RawGeomT implements flatbuffers.IGeneratedObject {
    geom: (number)[];
    constructor(geom?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=raw-geom.d.ts.map