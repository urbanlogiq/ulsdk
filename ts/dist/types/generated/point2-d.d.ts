import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class Point2D implements flatbuffers.IUnpackableObject<Point2DT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Point2D;
    x(): number;
    y(): number;
    static sizeOf(): number;
    static createPoint2D(builder: flatbuffers.Builder, x: number, y: number): flatbuffers.Offset;
    unpack(): Point2DT;
    unpackTo(_o: Point2DT): void;
}
export declare class Point2DT implements flatbuffers.IGeneratedObject {
    x: number;
    y: number;
    constructor(x?: number, y?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=point2-d.d.ts.map