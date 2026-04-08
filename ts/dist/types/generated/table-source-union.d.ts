import { Arrow } from './arrow';
import { DataCatalog } from './data-catalog';
import { Drive } from './drive';
import { GraphQuery } from './graph-query';
import { Placeholder } from './placeholder';
import { QueryTableSource } from './query-table-source';
import { Values } from './values';
import { Vector } from './vector';
export declare enum TableSourceUnion {
    NONE = 0,
    DataCatalog = 1,
    Arrow = 2,
    GraphQuery = 3,
    QueryTableSource = 4,
    Vector = 5,
    Placeholder = 6,
    Drive = 7,
    Values = 8
}
export declare function unionToTableSourceUnion(type: TableSourceUnion, accessor: (obj: Arrow | DataCatalog | Drive | GraphQuery | Placeholder | QueryTableSource | Values | Vector) => Arrow | DataCatalog | Drive | GraphQuery | Placeholder | QueryTableSource | Values | Vector | null): Arrow | DataCatalog | Drive | GraphQuery | Placeholder | QueryTableSource | Values | Vector | null;
export declare function unionListToTableSourceUnion(type: TableSourceUnion, accessor: (index: number, obj: Arrow | DataCatalog | Drive | GraphQuery | Placeholder | QueryTableSource | Values | Vector) => Arrow | DataCatalog | Drive | GraphQuery | Placeholder | QueryTableSource | Values | Vector | null, index: number): Arrow | DataCatalog | Drive | GraphQuery | Placeholder | QueryTableSource | Values | Vector | null;
//# sourceMappingURL=table-source-union.d.ts.map