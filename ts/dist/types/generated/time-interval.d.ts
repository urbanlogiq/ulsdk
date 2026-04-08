import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class TimeInterval implements flatbuffers.IUnpackableObject<TimeIntervalT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): TimeInterval;
    static getRootAsTimeInterval(bb: flatbuffers.ByteBuffer, obj?: TimeInterval): TimeInterval;
    static getSizePrefixedRootAsTimeInterval(bb: flatbuffers.ByteBuffer, obj?: TimeInterval): TimeInterval;
    min(): bigint;
    max(): bigint;
    static startTimeInterval(builder: flatbuffers.Builder): void;
    static addMin(builder: flatbuffers.Builder, min: bigint): void;
    static addMax(builder: flatbuffers.Builder, max: bigint): void;
    static endTimeInterval(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createTimeInterval(builder: flatbuffers.Builder, min: bigint, max: bigint): flatbuffers.Offset;
    unpack(): TimeIntervalT;
    unpackTo(_o: TimeIntervalT): void;
}
export declare class TimeIntervalT implements flatbuffers.IGeneratedObject {
    min: bigint;
    max: bigint;
    constructor(min?: bigint, max?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=time-interval.d.ts.map