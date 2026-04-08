import { NodeIdPair } from './node-id-pair';
import { RawGeom } from './raw-geom';
export declare enum GeometryDataUnion {
    NONE = 0,
    RawGeom = 1,
    NodeIdPair = 2
}
export declare function unionToGeometryDataUnion(type: GeometryDataUnion, accessor: (obj: NodeIdPair | RawGeom) => NodeIdPair | RawGeom | null): NodeIdPair | RawGeom | null;
export declare function unionListToGeometryDataUnion(type: GeometryDataUnion, accessor: (index: number, obj: NodeIdPair | RawGeom) => NodeIdPair | RawGeom | null, index: number): NodeIdPair | RawGeom | null;
//# sourceMappingURL=geometry-data-union.d.ts.map