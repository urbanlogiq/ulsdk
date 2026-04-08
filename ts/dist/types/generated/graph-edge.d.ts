import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { EdgeTy } from './edge-ty';
export declare class GraphEdge implements flatbuffers.IUnpackableObject<GraphEdgeT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): GraphEdge;
    static getRootAsGraphEdge(bb: flatbuffers.ByteBuffer, obj?: GraphEdge): GraphEdge;
    static getSizePrefixedRootAsGraphEdge(bb: flatbuffers.ByteBuffer, obj?: GraphEdge): GraphEdge;
    _Kind(): EdgeTy;
    _From(): bigint;
    _To(): bigint;
    static startGraphEdge(builder: flatbuffers.Builder): void;
    static add_kind(builder: flatbuffers.Builder, _Kind: EdgeTy): void;
    static add_from(builder: flatbuffers.Builder, _From: bigint): void;
    static add_to(builder: flatbuffers.Builder, _To: bigint): void;
    static endGraphEdge(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createGraphEdge(builder: flatbuffers.Builder, _Kind: EdgeTy, _From: bigint, _To: bigint): flatbuffers.Offset;
    unpack(): GraphEdgeT;
    unpackTo(_o: GraphEdgeT): void;
}
export declare class GraphEdgeT implements flatbuffers.IGeneratedObject {
    _Kind: EdgeTy;
    _From: bigint;
    _To: bigint;
    constructor(_Kind?: EdgeTy, _From?: bigint, _To?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=graph-edge.d.ts.map