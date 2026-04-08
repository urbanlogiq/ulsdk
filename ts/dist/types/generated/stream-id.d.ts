import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class StreamId implements flatbuffers.IUnpackableObject<StreamIdT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): StreamId;
    static getRootAsStreamId(bb: flatbuffers.ByteBuffer, obj?: StreamId): StreamId;
    static getSizePrefixedRootAsStreamId(bb: flatbuffers.ByteBuffer, obj?: StreamId): StreamId;
    b(index: number): number | null;
    bLength(): number;
    bArray(): Uint8Array | null;
    static startStreamId(builder: flatbuffers.Builder): void;
    static addB(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): void;
    static createBVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startBVector(builder: flatbuffers.Builder, numElems: number): void;
    static endStreamId(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createStreamId(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): StreamIdT;
    unpackTo(_o: StreamIdT): void;
}
export declare class StreamIdT implements flatbuffers.IGeneratedObject {
    b: (number)[];
    constructor(b?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=stream-id.d.ts.map