import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { GraphNode, GraphNodeT } from './graph-node';
export declare class NodeList implements flatbuffers.IUnpackableObject<NodeListT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NodeList;
    static getRootAsNodeList(bb: flatbuffers.ByteBuffer, obj?: NodeList): NodeList;
    static getSizePrefixedRootAsNodeList(bb: flatbuffers.ByteBuffer, obj?: NodeList): NodeList;
    nodes(index: number, obj?: GraphNode): GraphNode | null;
    nodesLength(): number;
    static startNodeList(builder: flatbuffers.Builder): void;
    static addNodes(builder: flatbuffers.Builder, nodesOffset: flatbuffers.Offset): void;
    static createNodesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startNodesVector(builder: flatbuffers.Builder, numElems: number): void;
    static endNodeList(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createNodeList(builder: flatbuffers.Builder, nodesOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): NodeListT;
    unpackTo(_o: NodeListT): void;
}
export declare class NodeListT implements flatbuffers.IGeneratedObject {
    nodes: (GraphNodeT)[];
    constructor(nodes?: (GraphNodeT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=node-list.d.ts.map