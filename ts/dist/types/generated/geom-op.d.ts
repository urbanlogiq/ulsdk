import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Fn } from './fn';
import { Geom, GeomT } from './geom';
import { Predicate } from './predicate';
export declare class GeomOp implements flatbuffers.IUnpackableObject<GeomOpT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): GeomOp;
    static getRootAsGeomOp(bb: flatbuffers.ByteBuffer, obj?: GeomOp): GeomOp;
    static getSizePrefixedRootAsGeomOp(bb: flatbuffers.ByteBuffer, obj?: GeomOp): GeomOp;
    op(): Fn;
    geoms(index: number, obj?: Geom): Geom | null;
    geomsLength(): number;
    predicate(): Predicate;
    static startGeomOp(builder: flatbuffers.Builder): void;
    static addOp(builder: flatbuffers.Builder, op: Fn): void;
    static addGeoms(builder: flatbuffers.Builder, geomsOffset: flatbuffers.Offset): void;
    static createGeomsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startGeomsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addPredicate(builder: flatbuffers.Builder, predicate: Predicate): void;
    static endGeomOp(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createGeomOp(builder: flatbuffers.Builder, op: Fn, geomsOffset: flatbuffers.Offset, predicate: Predicate): flatbuffers.Offset;
    unpack(): GeomOpT;
    unpackTo(_o: GeomOpT): void;
}
export declare class GeomOpT implements flatbuffers.IGeneratedObject {
    op: Fn;
    geoms: (GeomT)[];
    predicate: Predicate;
    constructor(op?: Fn, geoms?: (GeomT)[], predicate?: Predicate);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=geom-op.d.ts.map