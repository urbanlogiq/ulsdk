import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Expr, ExprT } from './expr';
import { Fn } from './fn';
export declare class Function implements flatbuffers.IUnpackableObject<FunctionT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Function;
    static getRootAsFunction(bb: flatbuffers.ByteBuffer, obj?: Function): Function;
    static getSizePrefixedRootAsFunction(bb: flatbuffers.ByteBuffer, obj?: Function): Function;
    fn(): Fn;
    parameters(index: number, obj?: Expr): Expr | null;
    parametersLength(): number;
    static startFunction(builder: flatbuffers.Builder): void;
    static addFn(builder: flatbuffers.Builder, fn: Fn): void;
    static addParameters(builder: flatbuffers.Builder, parametersOffset: flatbuffers.Offset): void;
    static createParametersVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startParametersVector(builder: flatbuffers.Builder, numElems: number): void;
    static endFunction(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createFunction(builder: flatbuffers.Builder, fn: Fn, parametersOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): FunctionT;
    unpackTo(_o: FunctionT): void;
}
export declare class FunctionT implements flatbuffers.IGeneratedObject {
    fn: Fn;
    parameters: (ExprT)[];
    constructor(fn?: Fn, parameters?: (ExprT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=function.d.ts.map