import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { EdgeTy } from './edge-ty';
export declare class EdgeQuery implements flatbuffers.IUnpackableObject<EdgeQueryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): EdgeQuery;
    static getRootAsEdgeQuery(bb: flatbuffers.ByteBuffer, obj?: EdgeQuery): EdgeQuery;
    static getSizePrefixedRootAsEdgeQuery(bb: flatbuffers.ByteBuffer, obj?: EdgeQuery): EdgeQuery;
    edgeTy(): EdgeTy;
    static startEdgeQuery(builder: flatbuffers.Builder): void;
    static addEdgeTy(builder: flatbuffers.Builder, edgeTy: EdgeTy): void;
    static endEdgeQuery(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createEdgeQuery(builder: flatbuffers.Builder, edgeTy: EdgeTy): flatbuffers.Offset;
    unpack(): EdgeQueryT;
    unpackTo(_o: EdgeQueryT): void;
}
export declare class EdgeQueryT implements flatbuffers.IGeneratedObject {
    edgeTy: EdgeTy;
    constructor(edgeTy?: EdgeTy);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=edge-query.d.ts.map