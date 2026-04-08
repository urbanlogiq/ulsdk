import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Precision } from './precision';
export declare class FloatingPoint implements flatbuffers.IUnpackableObject<FloatingPointT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): FloatingPoint;
    static getRootAsFloatingPoint(bb: flatbuffers.ByteBuffer, obj?: FloatingPoint): FloatingPoint;
    static getSizePrefixedRootAsFloatingPoint(bb: flatbuffers.ByteBuffer, obj?: FloatingPoint): FloatingPoint;
    precision(): Precision;
    static startFloatingPoint(builder: flatbuffers.Builder): void;
    static addPrecision(builder: flatbuffers.Builder, precision: Precision): void;
    static endFloatingPoint(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createFloatingPoint(builder: flatbuffers.Builder, precision: Precision): flatbuffers.Offset;
    unpack(): FloatingPointT;
    unpackTo(_o: FloatingPointT): void;
}
export declare class FloatingPointT implements flatbuffers.IGeneratedObject {
    precision: Precision;
    constructor(precision?: Precision);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=floating-point.d.ts.map