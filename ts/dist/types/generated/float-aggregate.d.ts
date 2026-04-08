import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { FloatBucket, FloatBucketT } from './float-bucket';
export declare class FloatAggregate implements flatbuffers.IUnpackableObject<FloatAggregateT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): FloatAggregate;
    static getRootAsFloatAggregate(bb: flatbuffers.ByteBuffer, obj?: FloatAggregate): FloatAggregate;
    static getSizePrefixedRootAsFloatAggregate(bb: flatbuffers.ByteBuffer, obj?: FloatAggregate): FloatAggregate;
    min(): number;
    max(): number;
    mean(): number;
    count(): bigint;
    sum(): number;
    variance(): number;
    histo(index: number, obj?: FloatBucket): FloatBucket | null;
    histoLength(): number;
    static startFloatAggregate(builder: flatbuffers.Builder): void;
    static addMin(builder: flatbuffers.Builder, min: number): void;
    static addMax(builder: flatbuffers.Builder, max: number): void;
    static addMean(builder: flatbuffers.Builder, mean: number): void;
    static addCount(builder: flatbuffers.Builder, count: bigint): void;
    static addSum(builder: flatbuffers.Builder, sum: number): void;
    static addVariance(builder: flatbuffers.Builder, variance: number): void;
    static addHisto(builder: flatbuffers.Builder, histoOffset: flatbuffers.Offset): void;
    static startHistoVector(builder: flatbuffers.Builder, numElems: number): void;
    static endFloatAggregate(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createFloatAggregate(builder: flatbuffers.Builder, min: number, max: number, mean: number, count: bigint, sum: number, variance: number, histoOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): FloatAggregateT;
    unpackTo(_o: FloatAggregateT): void;
}
export declare class FloatAggregateT implements flatbuffers.IGeneratedObject {
    min: number;
    max: number;
    mean: number;
    count: bigint;
    sum: number;
    variance: number;
    histo: (FloatBucketT)[];
    constructor(min?: number, max?: number, mean?: number, count?: bigint, sum?: number, variance?: number, histo?: (FloatBucketT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=float-aggregate.d.ts.map