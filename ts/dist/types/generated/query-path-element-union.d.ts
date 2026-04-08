import { EdgeQuery } from './edge-query';
import { NodeQuery } from './node-query';
export declare enum QueryPathElementUnion {
    NONE = 0,
    NodeQuery = 1,
    EdgeQuery = 2
}
export declare function unionToQueryPathElementUnion(type: QueryPathElementUnion, accessor: (obj: EdgeQuery | NodeQuery) => EdgeQuery | NodeQuery | null): EdgeQuery | NodeQuery | null;
export declare function unionListToQueryPathElementUnion(type: QueryPathElementUnion, accessor: (index: number, obj: EdgeQuery | NodeQuery) => EdgeQuery | NodeQuery | null, index: number): EdgeQuery | NodeQuery | null;
//# sourceMappingURL=query-path-element-union.d.ts.map