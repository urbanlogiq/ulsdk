import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Line, LineT } from './line';
/**
 * Polygon is an array of arrays of points.
 * The first array is exterior coords, following are any interior holes
 */
export declare class Polygon implements flatbuffers.IUnpackableObject<PolygonT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Polygon;
    static getRootAsPolygon(bb: flatbuffers.ByteBuffer, obj?: Polygon): Polygon;
    static getSizePrefixedRootAsPolygon(bb: flatbuffers.ByteBuffer, obj?: Polygon): Polygon;
    polygonGeo(index: number, obj?: Line): Line | null;
    polygonGeoLength(): number;
    static startPolygon(builder: flatbuffers.Builder): void;
    static addPolygonGeo(builder: flatbuffers.Builder, polygonGeoOffset: flatbuffers.Offset): void;
    static createPolygonGeoVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startPolygonGeoVector(builder: flatbuffers.Builder, numElems: number): void;
    static endPolygon(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createPolygon(builder: flatbuffers.Builder, polygonGeoOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): PolygonT;
    unpackTo(_o: PolygonT): void;
}
export declare class PolygonT implements flatbuffers.IGeneratedObject {
    polygonGeo: (LineT)[];
    constructor(polygonGeo?: (LineT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=polygon.d.ts.map