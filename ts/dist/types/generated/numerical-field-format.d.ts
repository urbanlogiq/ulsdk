import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { NumericalFieldValueType } from './numerical-field-value-type';
export declare class NumericalFieldFormat implements flatbuffers.IUnpackableObject<NumericalFieldFormatT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NumericalFieldFormat;
    static getRootAsNumericalFieldFormat(bb: flatbuffers.ByteBuffer, obj?: NumericalFieldFormat): NumericalFieldFormat;
    static getSizePrefixedRootAsNumericalFieldFormat(bb: flatbuffers.ByteBuffer, obj?: NumericalFieldFormat): NumericalFieldFormat;
    valueType(): NumericalFieldValueType;
    decimalPlaces(): number;
    scale(): number;
    offset(): number;
    static startNumericalFieldFormat(builder: flatbuffers.Builder): void;
    static addValueType(builder: flatbuffers.Builder, valueType: NumericalFieldValueType): void;
    static addDecimalPlaces(builder: flatbuffers.Builder, decimalPlaces: number): void;
    static addScale(builder: flatbuffers.Builder, scale: number): void;
    static addOffset(builder: flatbuffers.Builder, offset: number): void;
    static endNumericalFieldFormat(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createNumericalFieldFormat(builder: flatbuffers.Builder, valueType: NumericalFieldValueType, decimalPlaces: number, scale: number, offset: number): flatbuffers.Offset;
    unpack(): NumericalFieldFormatT;
    unpackTo(_o: NumericalFieldFormatT): void;
}
export declare class NumericalFieldFormatT implements flatbuffers.IGeneratedObject {
    valueType: NumericalFieldValueType;
    decimalPlaces: number;
    scale: number;
    offset: number;
    constructor(valueType?: NumericalFieldValueType, decimalPlaces?: number, scale?: number, offset?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=numerical-field-format.d.ts.map