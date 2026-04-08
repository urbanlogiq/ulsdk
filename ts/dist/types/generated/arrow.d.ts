import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class Arrow implements flatbuffers.IUnpackableObject<ArrowT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Arrow;
    static getRootAsArrow(bb: flatbuffers.ByteBuffer, obj?: Arrow): Arrow;
    static getSizePrefixedRootAsArrow(bb: flatbuffers.ByteBuffer, obj?: Arrow): Arrow;
    value(index: number): number | null;
    valueLength(): number;
    valueArray(): Uint8Array | null;
    static startArrow(builder: flatbuffers.Builder): void;
    static addValue(builder: flatbuffers.Builder, valueOffset: flatbuffers.Offset): void;
    static createValueVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startValueVector(builder: flatbuffers.Builder, numElems: number): void;
    static endArrow(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createArrow(builder: flatbuffers.Builder, valueOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ArrowT;
    unpackTo(_o: ArrowT): void;
}
export declare class ArrowT implements flatbuffers.IGeneratedObject {
    value: (number)[];
    constructor(value?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=arrow.d.ts.map