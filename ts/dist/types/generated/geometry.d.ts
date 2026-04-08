import { Line } from './line';
import { MultiLine } from './multi-line';
import { MultiPolygon } from './multi-polygon';
import { Point } from './point';
import { Polygon } from './polygon';
export declare enum Geometry {
    NONE = 0,
    Point = 1,
    Line = 2,
    MultiLine = 3,
    Polygon = 4,
    MultiPolygon = 5
}
export declare function unionToGeometry(type: Geometry, accessor: (obj: Line | MultiLine | MultiPolygon | Point | Polygon) => Line | MultiLine | MultiPolygon | Point | Polygon | null): Line | MultiLine | MultiPolygon | Point | Polygon | null;
export declare function unionListToGeometry(type: Geometry, accessor: (index: number, obj: Line | MultiLine | MultiPolygon | Point | Polygon) => Line | MultiLine | MultiPolygon | Point | Polygon | null, index: number): Line | MultiLine | MultiPolygon | Point | Polygon | null;
//# sourceMappingURL=geometry.d.ts.map