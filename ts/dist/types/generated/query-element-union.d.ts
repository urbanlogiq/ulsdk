import { BinaryQueryElement } from './binary-query-element';
import { DeleteQueryElement } from './delete-query-element';
import { InsertQueryElement } from './insert-query-element';
import { UnaryQueryElement } from './unary-query-element';
import { UpdateQueryElement } from './update-query-element';
export declare enum QueryElementUnion {
    NONE = 0,
    UnaryQueryElement = 1,
    BinaryQueryElement = 2,
    UpdateQueryElement = 3,
    DeleteQueryElement = 4,
    InsertQueryElement = 5
}
export declare function unionToQueryElementUnion(type: QueryElementUnion, accessor: (obj: BinaryQueryElement | DeleteQueryElement | InsertQueryElement | UnaryQueryElement | UpdateQueryElement) => BinaryQueryElement | DeleteQueryElement | InsertQueryElement | UnaryQueryElement | UpdateQueryElement | null): BinaryQueryElement | DeleteQueryElement | InsertQueryElement | UnaryQueryElement | UpdateQueryElement | null;
export declare function unionListToQueryElementUnion(type: QueryElementUnion, accessor: (index: number, obj: BinaryQueryElement | DeleteQueryElement | InsertQueryElement | UnaryQueryElement | UpdateQueryElement) => BinaryQueryElement | DeleteQueryElement | InsertQueryElement | UnaryQueryElement | UpdateQueryElement | null, index: number): BinaryQueryElement | DeleteQueryElement | InsertQueryElement | UnaryQueryElement | UpdateQueryElement | null;
//# sourceMappingURL=query-element-union.d.ts.map