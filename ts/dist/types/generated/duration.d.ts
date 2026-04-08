import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { TimeUnit } from './time-unit';
export declare class Duration implements flatbuffers.IUnpackableObject<DurationT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Duration;
    static getRootAsDuration(bb: flatbuffers.ByteBuffer, obj?: Duration): Duration;
    static getSizePrefixedRootAsDuration(bb: flatbuffers.ByteBuffer, obj?: Duration): Duration;
    unit(): TimeUnit;
    static startDuration(builder: flatbuffers.Builder): void;
    static addUnit(builder: flatbuffers.Builder, unit: TimeUnit): void;
    static endDuration(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDuration(builder: flatbuffers.Builder, unit: TimeUnit): flatbuffers.Offset;
    unpack(): DurationT;
    unpackTo(_o: DurationT): void;
}
export declare class DurationT implements flatbuffers.IGeneratedObject {
    unit: TimeUnit;
    constructor(unit?: TimeUnit);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=duration.d.ts.map