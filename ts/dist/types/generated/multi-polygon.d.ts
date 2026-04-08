import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Polygon, PolygonT } from './polygon';
export declare class MultiPolygon implements flatbuffers.IUnpackableObject<MultiPolygonT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): MultiPolygon;
    static getRootAsMultiPolygon(bb: flatbuffers.ByteBuffer, obj?: MultiPolygon): MultiPolygon;
    static getSizePrefixedRootAsMultiPolygon(bb: flatbuffers.ByteBuffer, obj?: MultiPolygon): MultiPolygon;
    multipolygonGeo(index: number, obj?: Polygon): Polygon | null;
    multipolygonGeoLength(): number;
    static startMultiPolygon(builder: flatbuffers.Builder): void;
    static addMultipolygonGeo(builder: flatbuffers.Builder, multipolygonGeoOffset: flatbuffers.Offset): void;
    static createMultipolygonGeoVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startMultipolygonGeoVector(builder: flatbuffers.Builder, numElems: number): void;
    static endMultiPolygon(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createMultiPolygon(builder: flatbuffers.Builder, multipolygonGeoOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): MultiPolygonT;
    unpackTo(_o: MultiPolygonT): void;
}
export declare class MultiPolygonT implements flatbuffers.IGeneratedObject {
    multipolygonGeo: (PolygonT)[];
    constructor(multipolygonGeo?: (PolygonT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=multi-polygon.d.ts.map