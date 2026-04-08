import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { UIntBucket, UIntBucketT } from './uint-bucket';
export declare class UIntAggregate implements flatbuffers.IUnpackableObject<UIntAggregateT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): UIntAggregate;
    static getRootAsUIntAggregate(bb: flatbuffers.ByteBuffer, obj?: UIntAggregate): UIntAggregate;
    static getSizePrefixedRootAsUIntAggregate(bb: flatbuffers.ByteBuffer, obj?: UIntAggregate): UIntAggregate;
    min(): bigint;
    max(): bigint;
    mean(): bigint;
    count(): bigint;
    sum(): bigint;
    variance(): bigint;
    histo(index: number, obj?: UIntBucket): UIntBucket | null;
    histoLength(): number;
    static startUIntAggregate(builder: flatbuffers.Builder): void;
    static addMin(builder: flatbuffers.Builder, min: bigint): void;
    static addMax(builder: flatbuffers.Builder, max: bigint): void;
    static addMean(builder: flatbuffers.Builder, mean: bigint): void;
    static addCount(builder: flatbuffers.Builder, count: bigint): void;
    static addSum(builder: flatbuffers.Builder, sum: bigint): void;
    static addVariance(builder: flatbuffers.Builder, variance: bigint): void;
    static addHisto(builder: flatbuffers.Builder, histoOffset: flatbuffers.Offset): void;
    static startHistoVector(builder: flatbuffers.Builder, numElems: number): void;
    static endUIntAggregate(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createUIntAggregate(builder: flatbuffers.Builder, min: bigint, max: bigint, mean: bigint, count: bigint, sum: bigint, variance: bigint, histoOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): UIntAggregateT;
    unpackTo(_o: UIntAggregateT): void;
}
export declare class UIntAggregateT implements flatbuffers.IGeneratedObject {
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
//# sourceMappingURL=uint-aggregate.d.ts.map