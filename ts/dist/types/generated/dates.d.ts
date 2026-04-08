import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class Dates implements flatbuffers.IUnpackableObject<DatesT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Dates;
    static getRootAsDates(bb: flatbuffers.ByteBuffer, obj?: Dates): Dates;
    static getSizePrefixedRootAsDates(bb: flatbuffers.ByteBuffer, obj?: Dates): Dates;
    min(): bigint;
    max(): bigint;
    uniqueValues(index: number): bigint | null;
    uniqueValuesLength(): number;
    uniqueValueCounts(index: number): number | null;
    uniqueValueCountsLength(): number;
    uniqueValueCountsArray(): Uint32Array | null;
    static startDates(builder: flatbuffers.Builder): void;
    static addMin(builder: flatbuffers.Builder, min: bigint): void;
    static addMax(builder: flatbuffers.Builder, max: bigint): void;
    static addUniqueValues(builder: flatbuffers.Builder, uniqueValuesOffset: flatbuffers.Offset): void;
    static createUniqueValuesVector(builder: flatbuffers.Builder, data: bigint[]): flatbuffers.Offset;
    static startUniqueValuesVector(builder: flatbuffers.Builder, numElems: number): void;
    static addUniqueValueCounts(builder: flatbuffers.Builder, uniqueValueCountsOffset: flatbuffers.Offset): void;
    static createUniqueValueCountsVector(builder: flatbuffers.Builder, data: number[] | Uint32Array): flatbuffers.Offset;
    /**
     * @deprecated This Uint8Array overload will be removed in the future.
     */
    static createUniqueValueCountsVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startUniqueValueCountsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endDates(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDates(builder: flatbuffers.Builder, min: bigint, max: bigint, uniqueValuesOffset: flatbuffers.Offset, uniqueValueCountsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DatesT;
    unpackTo(_o: DatesT): void;
}
export declare class DatesT implements flatbuffers.IGeneratedObject {
    min: bigint;
    max: bigint;
    uniqueValues: (bigint)[];
    uniqueValueCounts: (number)[];
    constructor(min?: bigint, max?: bigint, uniqueValues?: (bigint)[], uniqueValueCounts?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=dates.d.ts.map