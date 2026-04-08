import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { GraphNodeId, GraphNodeIdT } from './graph-node-id';
import { ObjectId, ObjectIdT } from './object-id';
export declare class NodeIdPair implements flatbuffers.IUnpackableObject<NodeIdPairT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NodeIdPair;
    static getRootAsNodeIdPair(bb: flatbuffers.ByteBuffer, obj?: NodeIdPair): NodeIdPair;
    static getSizePrefixedRootAsNodeIdPair(bb: flatbuffers.ByteBuffer, obj?: NodeIdPair): NodeIdPair;
    streamId(obj?: ObjectId): ObjectId | null;
    nodeId(obj?: GraphNodeId): GraphNodeId | null;
    static startNodeIdPair(builder: flatbuffers.Builder): void;
    static addStreamId(builder: flatbuffers.Builder, streamIdOffset: flatbuffers.Offset): void;
    static addNodeId(builder: flatbuffers.Builder, nodeIdOffset: flatbuffers.Offset): void;
    static endNodeIdPair(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): NodeIdPairT;
    unpackTo(_o: NodeIdPairT): void;
}
export declare class NodeIdPairT implements flatbuffers.IGeneratedObject {
    streamId: ObjectIdT | null;
    nodeId: GraphNodeIdT | null;
    constructor(streamId?: ObjectIdT | null, nodeId?: GraphNodeIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=node-id-pair.d.ts.map