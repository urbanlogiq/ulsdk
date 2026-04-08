import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class GraphNodeId implements flatbuffers.IUnpackableObject<GraphNodeIdT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): GraphNodeId;
    static getRootAsGraphNodeId(bb: flatbuffers.ByteBuffer, obj?: GraphNodeId): GraphNodeId;
    static getSizePrefixedRootAsGraphNodeId(bb: flatbuffers.ByteBuffer, obj?: GraphNodeId): GraphNodeId;
    b(index: number): number | null;
    bLength(): number;
    bArray(): Uint8Array | null;
    static startGraphNodeId(builder: flatbuffers.Builder): void;
    static addB(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): void;
    static createBVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startBVector(builder: flatbuffers.Builder, numElems: number): void;
    static endGraphNodeId(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createGraphNodeId(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): GraphNodeIdT;
    unpackTo(_o: GraphNodeIdT): void;
}
export declare class GraphNodeIdT implements flatbuffers.IGeneratedObject {
    b: (number)[];
    constructor(b?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=graph-node-id.d.ts.map