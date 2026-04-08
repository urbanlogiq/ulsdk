import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Point2D, Point2DT } from './point2-d';
export declare class Tri2D implements flatbuffers.IUnpackableObject<Tri2DT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Tri2D;
    p0(obj?: Point2D): Point2D | null;
    p1(obj?: Point2D): Point2D | null;
    p2(obj?: Point2D): Point2D | null;
    static sizeOf(): number;
    static createTri2D(builder: flatbuffers.Builder, p0_x: number, p0_y: number, p1_x: number, p1_y: number, p2_x: number, p2_y: number): flatbuffers.Offset;
    unpack(): Tri2DT;
    unpackTo(_o: Tri2DT): void;
}
export declare class Tri2DT implements flatbuffers.IGeneratedObject {
    p0: Point2DT | null;
    p1: Point2DT | null;
    p2: Point2DT | null;
    constructor(p0?: Point2DT | null, p1?: Point2DT | null, p2?: Point2DT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=tri2-d.d.ts.map