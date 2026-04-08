import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class Edge implements flatbuffers.IUnpackableObject<EdgeT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Edge;
    static getRootAsEdge(bb: flatbuffers.ByteBuffer, obj?: Edge): Edge;
    static getSizePrefixedRootAsEdge(bb: flatbuffers.ByteBuffer, obj?: Edge): Edge;
    from(): number;
    to(): number;
    static startEdge(builder: flatbuffers.Builder): void;
    static addFrom(builder: flatbuffers.Builder, from: number): void;
    static addTo(builder: flatbuffers.Builder, to: number): void;
    static endEdge(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createEdge(builder: flatbuffers.Builder, from: number, to: number): flatbuffers.Offset;
    unpack(): EdgeT;
    unpackTo(_o: EdgeT): void;
}
export declare class EdgeT implements flatbuffers.IGeneratedObject {
    from: number;
    to: number;
    constructor(from?: number, to?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=edge.d.ts.map