import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { UIntBucket, UIntBucketT } from './uint-bucket';
export declare class IntAggregate implements flatbuffers.IUnpackableObject<IntAggregateT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): IntAggregate;
    static getRootAsIntAggregate(bb: flatbuffers.ByteBuffer, obj?: IntAggregate): IntAggregate;
    static getSizePrefixedRootAsIntAggregate(bb: flatbuffers.ByteBuffer, obj?: IntAggregate): IntAggregate;
    min(): bigint;
    max(): bigint;
    mean(): bigint;
    count(): bigint;
    sum(): bigint;
    variance(): bigint;
    histo(index: number, obj?: UIntBucket): UIntBucket | null;
    histoLength(): number;
    static startIntAggregate(builder: flatbuffers.Builder): void;
    static addMin(builder: flatbuffers.Builder, min: bigint): void;
    static addMax(builder: flatbuffers.Builder, max: bigint): void;
    static addMean(builder: flatbuffers.Builder, mean: bigint): void;
    static addCount(builder: flatbuffers.Builder, count: bigint): void;
    static addSum(builder: flatbuffers.Builder, sum: bigint): void;
    static addVariance(builder: flatbuffers.Builder, variance: bigint): void;
    static addHisto(builder: flatbuffers.Builder, histoOffset: flatbuffers.Offset): void;
    static startHistoVector(builder: flatbuffers.Builder, numElems: number): void;
    static endIntAggregate(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createIntAggregate(builder: flatbuffers.Builder, min: bigint, max: bigint, mean: bigint, count: bigint, sum: bigint, variance: bigint, histoOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): IntAggregateT;
    unpackTo(_o: IntAggregateT): void;
}
export declare class IntAggregateT implements flatbuffers.IGeneratedObject {
    min: bigint;
    max: bigint;
    mean: bigint;
    count: bigint;
    sum: bigint;
    variance: bigint;
    histo: (UIntBucketT)[];
    constructor(min?: bigint, max?: bigint, mean?: bigint, count?: bigint, sum?: bigint, variance?: bigint, histo?: (UIntBucketT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=int-aggregate.d.ts.map