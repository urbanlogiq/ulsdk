import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class Placeholder implements flatbuffers.IUnpackableObject<PlaceholderT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Placeholder;
    static getRootAsPlaceholder(bb: flatbuffers.ByteBuffer, obj?: Placeholder): Placeholder;
    static getSizePrefixedRootAsPlaceholder(bb: flatbuffers.ByteBuffer, obj?: Placeholder): Placeholder;
    idx(): number;
    static startPlaceholder(builder: flatbuffers.Builder): void;
    static addIdx(builder: flatbuffers.Builder, idx: number): void;
    static endPlaceholder(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createPlaceholder(builder: flatbuffers.Builder, idx: number): flatbuffers.Offset;
    unpack(): PlaceholderT;
    unpackTo(_o: PlaceholderT): void;
}
export declare class PlaceholderT implements flatbuffers.IGeneratedObject {
    idx: number;
    constructor(idx?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=placeholder.d.ts.map