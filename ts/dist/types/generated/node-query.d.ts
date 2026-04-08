import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { EntityTy } from './entity-ty';
import { GeomOp, GeomOpT } from './geom-op';
import { NodeIdPair, NodeIdPairT } from './node-id-pair';
import { ObjectId, ObjectIdT } from './object-id';
import { Projection, ProjectionT } from './projection';
export declare class NodeQuery implements flatbuffers.IUnpackableObject<NodeQueryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NodeQuery;
    static getRootAsNodeQuery(bb: flatbuffers.ByteBuffer, obj?: NodeQuery): NodeQuery;
    static getSizePrefixedRootAsNodeQuery(bb: flatbuffers.ByteBuffer, obj?: NodeQuery): NodeQuery;
    streamIds(index: number, obj?: ObjectId): ObjectId | null;
    streamIdsLength(): number;
    entityTys(index: number): EntityTy | null;
    entityTysLength(): number;
    entityTysArray(): Int32Array | null;
    /**
     * If descriptions are provided here, then results will be ordered by their string similarity to the
     * descriptions here. This ordering is secondary to the any top-level order_by that might be provided.
     */
    descriptions(index: number): string;
    descriptions(index: number, optionalEncoding: flatbuffers.Encoding): string | Uint8Array;
    descriptionsLength(): number;
    nodeIds(index: number, obj?: NodeIdPair): NodeIdPair | null;
    nodeIdsLength(): number;
    projections(index: number, obj?: Projection): Projection | null;
    projectionsLength(): number;
    geomOp(obj?: GeomOp): GeomOp | null;
    static startNodeQuery(builder: flatbuffers.Builder): void;
    static addStreamIds(builder: flatbuffers.Builder, streamIdsOffset: flatbuffers.Offset): void;
    static createStreamIdsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startStreamIdsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addEntityTys(builder: flatbuffers.Builder, entityTysOffset: flatbuffers.Offset): void;
    static createEntityTysVector(builder: flatbuffers.Builder, data: EntityTy[]): flatbuffers.Offset;
    static startEntityTysVector(builder: flatbuffers.Builder, numElems: number): void;
    static addDescriptions(builder: flatbuffers.Builder, descriptionsOffset: flatbuffers.Offset): void;
    static createDescriptionsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startDescriptionsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addNodeIds(builder: flatbuffers.Builder, nodeIdsOffset: flatbuffers.Offset): void;
    static createNodeIdsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startNodeIdsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addProjections(builder: flatbuffers.Builder, projectionsOffset: flatbuffers.Offset): void;
    static createProjectionsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startProjectionsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addGeomOp(builder: flatbuffers.Builder, geomOpOffset: flatbuffers.Offset): void;
    static endNodeQuery(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): NodeQueryT;
    unpackTo(_o: NodeQueryT): void;
}
export declare class NodeQueryT implements flatbuffers.IGeneratedObject {
    streamIds: (ObjectIdT)[];
    entityTys: (EntityTy)[];
    descriptions: (string)[];
    nodeIds: (NodeIdPairT)[];
    projections: (ProjectionT)[];
    geomOp: GeomOpT | null;
    constructor(streamIds?: (ObjectIdT)[], entityTys?: (EntityTy)[], descriptions?: (string)[], nodeIds?: (NodeIdPairT)[], projections?: (ProjectionT)[], geomOp?: GeomOpT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=node-query.d.ts.map