import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { IntervalUnit } from './interval-unit';
export declare class Interval implements flatbuffers.IUnpackableObject<IntervalT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Interval;
    static getRootAsInterval(bb: flatbuffers.ByteBuffer, obj?: Interval): Interval;
    static getSizePrefixedRootAsInterval(bb: flatbuffers.ByteBuffer, obj?: Interval): Interval;
    unit(): IntervalUnit;
    static startInterval(builder: flatbuffers.Builder): void;
    static addUnit(builder: flatbuffers.Builder, unit: IntervalUnit): void;
    static endInterval(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createInterval(builder: flatbuffers.Builder, unit: IntervalUnit): flatbuffers.Offset;
    unpack(): IntervalT;
    unpackTo(_o: IntervalT): void;
}
export declare class IntervalT implements flatbuffers.IGeneratedObject {
    unit: IntervalUnit;
    constructor(unit?: IntervalUnit);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=interval.d.ts.map