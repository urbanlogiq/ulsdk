import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Geometry } from './geometry';
import { LineT } from './line';
import { MultiLineT } from './multi-line';
import { MultiPolygonT } from './multi-polygon';
import { PointT } from './point';
import { PolygonT } from './polygon';
export declare class Geom implements flatbuffers.IUnpackableObject<GeomT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Geom;
    static getRootAsGeom(bb: flatbuffers.ByteBuffer, obj?: Geom): Geom;
    static getSizePrefixedRootAsGeom(bb: flatbuffers.ByteBuffer, obj?: Geom): Geom;
    geomType(): Geometry;
    geom<T extends flatbuffers.Table>(obj: any): any | null;
    static startGeom(builder: flatbuffers.Builder): void;
    static addGeomType(builder: flatbuffers.Builder, geomType: Geometry): void;
    static addGeom(builder: flatbuffers.Builder, geomOffset: flatbuffers.Offset): void;
    static endGeom(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createGeom(builder: flatbuffers.Builder, geomType: Geometry, geomOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): GeomT;
    unpackTo(_o: GeomT): void;
}
export declare class GeomT implements flatbuffers.IGeneratedObject {
    geomType: Geometry;
    geom: LineT | MultiLineT | MultiPolygonT | PointT | PolygonT | null;
    constructor(geomType?: Geometry, geom?: LineT | MultiLineT | MultiPolygonT | PointT | PolygonT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=geom.d.ts.map