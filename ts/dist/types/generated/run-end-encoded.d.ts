import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * Contains two child arrays, run_ends and values.
 * The run_ends child array must be a 16/32/64-bit integer array
 * which encodes the indices at which the run with the value in
 * each corresponding index in the values child array ends.
 * Like list/struct types, the value array can be of any type.
 */
export declare class RunEndEncoded implements flatbuffers.IUnpackableObject<RunEndEncodedT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): RunEndEncoded;
    static getRootAsRunEndEncoded(bb: flatbuffers.ByteBuffer, obj?: RunEndEncoded): RunEndEncoded;
    static getSizePrefixedRootAsRunEndEncoded(bb: flatbuffers.ByteBuffer, obj?: RunEndEncoded): RunEndEncoded;
    static startRunEndEncoded(builder: flatbuffers.Builder): void;
    static endRunEndEncoded(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createRunEndEncoded(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): RunEndEncodedT;
    unpackTo(_o: RunEndEncodedT): void;
}
export declare class RunEndEncodedT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=run-end-encoded.d.ts.map