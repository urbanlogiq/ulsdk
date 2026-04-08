import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { TimeInterval, TimeIntervalT } from './time-interval';
export declare class DatetimeRange implements flatbuffers.IUnpackableObject<DatetimeRangeT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DatetimeRange;
    static getRootAsDatetimeRange(bb: flatbuffers.ByteBuffer, obj?: DatetimeRange): DatetimeRange;
    static getSizePrefixedRootAsDatetimeRange(bb: flatbuffers.ByteBuffer, obj?: DatetimeRange): DatetimeRange;
    min(): bigint;
    max(): bigint;
    intervals(index: number, obj?: TimeInterval): TimeInterval | null;
    intervalsLength(): number;
    static startDatetimeRange(builder: flatbuffers.Builder): void;
    static addMin(builder: flatbuffers.Builder, min: bigint): void;
    static addMax(builder: flatbuffers.Builder, max: bigint): void;
    static addIntervals(builder: flatbuffers.Builder, intervalsOffset: flatbuffers.Offset): void;
    static createIntervalsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startIntervalsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endDatetimeRange(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDatetimeRange(builder: flatbuffers.Builder, min: bigint, max: bigint, intervalsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DatetimeRangeT;
    unpackTo(_o: DatetimeRangeT): void;
}
export declare class DatetimeRangeT implements flatbuffers.IGeneratedObject {
    min: bigint;
    max: bigint;
    intervals: (TimeIntervalT)[];
    constructor(min?: bigint, max?: bigint, intervals?: (TimeIntervalT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=datetime-range.d.ts.map