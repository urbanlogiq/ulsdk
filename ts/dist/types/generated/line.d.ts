import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Point, PointT } from './point';
export declare class Line implements flatbuffers.IUnpackableObject<LineT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Line;
    static getRootAsLine(bb: flatbuffers.ByteBuffer, obj?: Line): Line;
    static getSizePrefixedRootAsLine(bb: flatbuffers.ByteBuffer, obj?: Line): Line;
    lineGeo(index: number, obj?: Point): Point | null;
    lineGeoLength(): number;
    static startLine(builder: flatbuffers.Builder): void;
    static addLineGeo(builder: flatbuffers.Builder, lineGeoOffset: flatbuffers.Offset): void;
    static createLineGeoVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startLineGeoVector(builder: flatbuffers.Builder, numElems: number): void;
    static endLine(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createLine(builder: flatbuffers.Builder, lineGeoOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): LineT;
    unpackTo(_o: LineT): void;
}
export declare class LineT implements flatbuffers.IGeneratedObject {
    lineGeo: (PointT)[];
    constructor(lineGeo?: (PointT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=line.d.ts.map