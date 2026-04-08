import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class Point implements flatbuffers.IUnpackableObject<PointT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Point;
    static getRootAsPoint(bb: flatbuffers.ByteBuffer, obj?: Point): Point;
    static getSizePrefixedRootAsPoint(bb: flatbuffers.ByteBuffer, obj?: Point): Point;
    pointGeo(index: number): number | null;
    pointGeoLength(): number;
    pointGeoArray(): Float32Array | null;
    static startPoint(builder: flatbuffers.Builder): void;
    static addPointGeo(builder: flatbuffers.Builder, pointGeoOffset: flatbuffers.Offset): void;
    static createPointGeoVector(builder: flatbuffers.Builder, data: number[] | Float32Array): flatbuffers.Offset;
    /**
     * @deprecated This Uint8Array overload will be removed in the future.
     */
    static createPointGeoVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startPointGeoVector(builder: flatbuffers.Builder, numElems: number): void;
    static endPoint(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createPoint(builder: flatbuffers.Builder, pointGeoOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): PointT;
    unpackTo(_o: PointT): void;
}
export declare class PointT implements flatbuffers.IGeneratedObject {
    pointGeo: (number)[];
    constructor(pointGeo?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=point.d.ts.map