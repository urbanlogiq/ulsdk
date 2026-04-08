import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { AggregationFunction } from './aggregation-function';
import { NumericalFieldFormat, NumericalFieldFormatT } from './numerical-field-format';
export declare class FloatRange implements flatbuffers.IUnpackableObject<FloatRangeT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): FloatRange;
    static getRootAsFloatRange(bb: flatbuffers.ByteBuffer, obj?: FloatRange): FloatRange;
    static getSizePrefixedRootAsFloatRange(bb: flatbuffers.ByteBuffer, obj?: FloatRange): FloatRange;
    min(): number;
    max(): number;
    fieldFormat(obj?: NumericalFieldFormat): NumericalFieldFormat | null;
    aggregationProtocol(): AggregationFunction;
    static startFloatRange(builder: flatbuffers.Builder): void;
    static addMin(builder: flatbuffers.Builder, min: number): void;
    static addMax(builder: flatbuffers.Builder, max: number): void;
    static addFieldFormat(builder: flatbuffers.Builder, fieldFormatOffset: flatbuffers.Offset): void;
    static addAggregationProtocol(builder: flatbuffers.Builder, aggregationProtocol: AggregationFunction): void;
    static endFloatRange(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): FloatRangeT;
    unpackTo(_o: FloatRangeT): void;
}
export declare class FloatRangeT implements flatbuffers.IGeneratedObject {
    min: number;
    max: number;
    fieldFormat: NumericalFieldFormatT | null;
    aggregationProtocol: AggregationFunction;
    constructor(min?: number, max?: number, fieldFormat?: NumericalFieldFormatT | null, aggregationProtocol?: AggregationFunction);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=float-range.d.ts.map