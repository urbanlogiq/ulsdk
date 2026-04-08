import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { EntityTy } from './entity-ty';
import { GenericId, GenericIdT } from './generic-id';
import { Geometry } from './geometry';
import { LineT } from './line';
import { MultiLineT } from './multi-line';
import { MultiPolygonT } from './multi-polygon';
import { NodeTy } from './node-ty';
import { ObjectId, ObjectIdT } from './object-id';
import { Point, PointT } from './point';
import { PolygonT } from './polygon';
export declare class GraphNode implements flatbuffers.IUnpackableObject<GraphNodeT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): GraphNode;
    static getRootAsGraphNode(bb: flatbuffers.ByteBuffer, obj?: GraphNode): GraphNode;
    static getSizePrefixedRootAsGraphNode(bb: flatbuffers.ByteBuffer, obj?: GraphNode): GraphNode;
    /**
     * Entity type (ie: traffic loop, road, power line, building, business, demographic data, collision,  ...)
     */
    _EntityType(): EntityTy;
    /**
     * Node type, such as emitter vs. entity
     */
    _NodeType(): NodeTy;
    /**
     * ID of the associated data source
     */
    _Stream(obj?: ObjectId): ObjectId | null;
    /**
     * Record id in the data source.
     */
    _NodeId(obj?: GenericId): GenericId | null;
    /**
     * lat/lng point in space, or centroid if not a point
     */
    _Location(obj?: Point): Point | null;
    _GeomType(): Geometry;
    /**
     * polygon / line / point / null
     */
    _Geom<T extends flatbuffers.Table>(obj: any): any | null;
    /**
     * A human-centric description of this graph node.
     */
    _Description(): string | null;
    _Description(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    /**
     * Unique database-specific identifier
     */
    _Uid(): bigint;
    static startGraphNode(builder: flatbuffers.Builder): void;
    static add_entityType(builder: flatbuffers.Builder, _EntityType: EntityTy): void;
    static add_nodeType(builder: flatbuffers.Builder, _NodeType: NodeTy): void;
    static add_stream(builder: flatbuffers.Builder, _StreamOffset: flatbuffers.Offset): void;
    static add_nodeId(builder: flatbuffers.Builder, _NodeIdOffset: flatbuffers.Offset): void;
    static add_location(builder: flatbuffers.Builder, _LocationOffset: flatbuffers.Offset): void;
    static add_geomType(builder: flatbuffers.Builder, _GeomType: Geometry): void;
    static add_geom(builder: flatbuffers.Builder, _GeomOffset: flatbuffers.Offset): void;
    static add_description(builder: flatbuffers.Builder, _DescriptionOffset: flatbuffers.Offset): void;
    static add_uid(builder: flatbuffers.Builder, _Uid: bigint): void;
    static endGraphNode(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): GraphNodeT;
    unpackTo(_o: GraphNodeT): void;
}
export declare class GraphNodeT implements flatbuffers.IGeneratedObject {
    _EntityType: EntityTy;
    _NodeType: NodeTy;
    _Stream: ObjectIdT | null;
    _NodeId: GenericIdT | null;
    _Location: PointT | null;
    _GeomType: Geometry;
    _Geom: LineT | MultiLineT | MultiPolygonT | PointT | PolygonT | null;
    _Description: string | Uint8Array | null;
    _Uid: bigint;
    constructor(_EntityType?: EntityTy, _NodeType?: NodeTy, _Stream?: ObjectIdT | null, _NodeId?: GenericIdT | null, _Location?: PointT | null, _GeomType?: Geometry, _Geom?: LineT | MultiLineT | MultiPolygonT | PointT | PolygonT | null, _Description?: string | Uint8Array | null, _Uid?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=graph-node.d.ts.map