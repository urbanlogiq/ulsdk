import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { GraphEdge, GraphEdgeT } from './graph-edge';
export declare class EdgeList implements flatbuffers.IUnpackableObject<EdgeListT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): EdgeList;
    static getRootAsEdgeList(bb: flatbuffers.ByteBuffer, obj?: EdgeList): EdgeList;
    static getSizePrefixedRootAsEdgeList(bb: flatbuffers.ByteBuffer, obj?: EdgeList): EdgeList;
    edges(index: number, obj?: GraphEdge): GraphEdge | null;
    edgesLength(): number;
    static startEdgeList(builder: flatbuffers.Builder): void;
    static addEdges(builder: flatbuffers.Builder, edgesOffset: flatbuffers.Offset): void;
    static createEdgesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startEdgesVector(builder: flatbuffers.Builder, numElems: number): void;
    static endEdgeList(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createEdgeList(builder: flatbuffers.Builder, edgesOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): EdgeListT;
    unpackTo(_o: EdgeListT): void;
}
export declare class EdgeListT implements flatbuffers.IGeneratedObject {
    edges: (GraphEdgeT)[];
    constructor(edges?: (GraphEdgeT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=edge-list.d.ts.map