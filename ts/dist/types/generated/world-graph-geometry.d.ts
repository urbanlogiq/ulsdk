import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { EdgeTy } from './edge-ty';
import { ObjectId, ObjectIdT } from './object-id';
/**
 * For most streams with GeometrySourceType==WorldGraphGeometry, edge_path will
 * be empty and start_stream_id will be unset.
 *
 * If edge_path is empty and start_stream_id is unset we just query for nodes
 * whose stream predicate matches this stream's streamId in order to fetch the stream's geometry.
 *
 * If edge_path is non-empty and start_stream_id is set: Start at nodes with
 * streamId=start_stream_id and follow the edge_path. Retrieve geometry from
 * the last node on that path.
 *
 * If edge_path is non-empty and start_stream_id is unset: Start at nodes with
 * streamId=id of this stream and follow the edge_path to retrieve the geeometry.
 *
 * If edge_path is empty and start_stream_id is set: Just query for nodes with
 * streamId == start_stream_id.
 */
export declare class WorldGraphGeometry implements flatbuffers.IUnpackableObject<WorldGraphGeometryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): WorldGraphGeometry;
    static getRootAsWorldGraphGeometry(bb: flatbuffers.ByteBuffer, obj?: WorldGraphGeometry): WorldGraphGeometry;
    static getSizePrefixedRootAsWorldGraphGeometry(bb: flatbuffers.ByteBuffer, obj?: WorldGraphGeometry): WorldGraphGeometry;
    /**
     * Edges to follow to reach the nodes with geometry.
     */
    edgePath(index: number): EdgeTy | null;
    edgePathLength(): number;
    edgePathArray(): Int32Array | null;
    /**
     * Stream id of the starting node in the query path for the geometry
     */
    startStreamId(obj?: ObjectId): ObjectId | null;
    static startWorldGraphGeometry(builder: flatbuffers.Builder): void;
    static addEdgePath(builder: flatbuffers.Builder, edgePathOffset: flatbuffers.Offset): void;
    static createEdgePathVector(builder: flatbuffers.Builder, data: EdgeTy[]): flatbuffers.Offset;
    static startEdgePathVector(builder: flatbuffers.Builder, numElems: number): void;
    static addStartStreamId(builder: flatbuffers.Builder, startStreamIdOffset: flatbuffers.Offset): void;
    static endWorldGraphGeometry(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): WorldGraphGeometryT;
    unpackTo(_o: WorldGraphGeometryT): void;
}
export declare class WorldGraphGeometryT implements flatbuffers.IGeneratedObject {
    edgePath: (EdgeTy)[];
    startStreamId: ObjectIdT | null;
    constructor(edgePath?: (EdgeTy)[], startStreamId?: ObjectIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=world-graph-geometry.d.ts.map