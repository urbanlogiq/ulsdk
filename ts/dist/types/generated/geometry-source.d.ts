import { DatacatalogGeometry } from './datacatalog-geometry';
import { NoGeometry } from './no-geometry';
import { WorldGraphGeometry } from './world-graph-geometry';
export declare enum GeometrySource {
    NONE = 0,
    NoGeometry = 1,
    DatacatalogGeometry = 2,
    WorldGraphGeometry = 3
}
export declare function unionToGeometrySource(type: GeometrySource, accessor: (obj: DatacatalogGeometry | NoGeometry | WorldGraphGeometry) => DatacatalogGeometry | NoGeometry | WorldGraphGeometry | null): DatacatalogGeometry | NoGeometry | WorldGraphGeometry | null;
export declare function unionListToGeometrySource(type: GeometrySource, accessor: (index: number, obj: DatacatalogGeometry | NoGeometry | WorldGraphGeometry) => DatacatalogGeometry | NoGeometry | WorldGraphGeometry | null, index: number): DatacatalogGeometry | NoGeometry | WorldGraphGeometry | null;
//# sourceMappingURL=geometry-source.d.ts.map