import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { AggregationFunction } from './aggregation-function';
import { IntegerDisplayString, IntegerDisplayStringT } from './integer-display-string';
import { NumericalFieldFormat, NumericalFieldFormatT } from './numerical-field-format';
export declare class IntRange implements flatbuffers.IUnpackableObject<IntRangeT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): IntRange;
    static getRootAsIntRange(bb: flatbuffers.ByteBuffer, obj?: IntRange): IntRange;
    static getSizePrefixedRootAsIntRange(bb: flatbuffers.ByteBuffer, obj?: IntRange): IntRange;
    min(): bigint;
    max(): bigint;
    fieldFormat(obj?: NumericalFieldFormat): NumericalFieldFormat | null;
    aggregationProtocol(): AggregationFunction;
    displayStrings(index: number, obj?: IntegerDisplayString): IntegerDisplayString | null;
    displayStringsLength(): number;
    enumName(): string | null;
    enumName(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startIntRange(builder: flatbuffers.Builder): void;
    static addMin(builder: flatbuffers.Builder, min: bigint): void;
    static addMax(builder: flatbuffers.Builder, max: bigint): void;
    static addFieldFormat(builder: flatbuffers.Builder, fieldFormatOffset: flatbuffers.Offset): void;
    static addAggregationProtocol(builder: flatbuffers.Builder, aggregationProtocol: AggregationFunction): void;
    static addDisplayStrings(builder: flatbuffers.Builder, displayStringsOffset: flatbuffers.Offset): void;
    static createDisplayStringsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startDisplayStringsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addEnumName(builder: flatbuffers.Builder, enumNameOffset: flatbuffers.Offset): void;
    static endIntRange(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): IntRangeT;
    unpackTo(_o: IntRangeT): void;
}
export declare class IntRangeT implements flatbuffers.IGeneratedObject {
    min: bigint;
    max: bigint;
    fieldFormat: NumericalFieldFormatT | null;
    aggregationProtocol: AggregationFunction;
    displayStrings: (IntegerDisplayStringT)[];
    enumName: string | Uint8Array | null;
    constructor(min?: bigint, max?: bigint, fieldFormat?: NumericalFieldFormatT | null, aggregationProtocol?: AggregationFunction, displayStrings?: (IntegerDisplayStringT)[], enumName?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=int-range.d.ts.map