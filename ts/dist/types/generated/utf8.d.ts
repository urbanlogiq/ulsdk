import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * Unicode with UTF-8 encoding
 */
export declare class Utf8 implements flatbuffers.IUnpackableObject<Utf8T> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Utf8;
    static getRootAsUtf8(bb: flatbuffers.ByteBuffer, obj?: Utf8): Utf8;
    static getSizePrefixedRootAsUtf8(bb: flatbuffers.ByteBuffer, obj?: Utf8): Utf8;
    static startUtf8(builder: flatbuffers.Builder): void;
    static endUtf8(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createUtf8(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): Utf8T;
    unpackTo(_o: Utf8T): void;
}
export declare class Utf8T implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=utf8.d.ts.map