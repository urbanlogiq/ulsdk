import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class ValueIndex implements flatbuffers.IUnpackableObject<ValueIndexT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ValueIndex;
    static getRootAsValueIndex(bb: flatbuffers.ByteBuffer, obj?: ValueIndex): ValueIndex;
    static getSizePrefixedRootAsValueIndex(bb: flatbuffers.ByteBuffer, obj?: ValueIndex): ValueIndex;
    idx(): number;
    static startValueIndex(builder: flatbuffers.Builder): void;
    static addIdx(builder: flatbuffers.Builder, idx: number): void;
    static endValueIndex(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createValueIndex(builder: flatbuffers.Builder, idx: number): flatbuffers.Offset;
    unpack(): ValueIndexT;
    unpackTo(_o: ValueIndexT): void;
}
export declare class ValueIndexT implements flatbuffers.IGeneratedObject {
    idx: number;
    constructor(idx?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=value-index.d.ts.map