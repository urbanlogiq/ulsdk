import { AllColumns } from './all-columns';
import { Case } from './case';
import { Column } from './column';
import { Function } from './function';
import { OrderByExpr } from './order-by-expr';
import { Partition } from './partition';
import { UnsetArgument } from './unset-argument';
import { ValueIndex } from './value-index';
import { ValueName } from './value-name';
import { Window } from './window';
export declare enum ExprUnion {
    NONE = 0,
    ValueIndex = 1,
    Column = 2,
    Function = 3,
    AllColumns = 4,
    Case = 5,
    OrderByExpr = 6,
    Partition = 7,
    UnsetArgument = 8,
    Window = 9,
    ValueName = 10
}
export declare function unionToExprUnion(type: ExprUnion, accessor: (obj: AllColumns | Case | Column | Function | OrderByExpr | Partition | UnsetArgument | ValueIndex | ValueName | Window) => AllColumns | Case | Column | Function | OrderByExpr | Partition | UnsetArgument | ValueIndex | ValueName | Window | null): AllColumns | Case | Column | Function | OrderByExpr | Partition | UnsetArgument | ValueIndex | ValueName | Window | null;
export declare function unionListToExprUnion(type: ExprUnion, accessor: (index: number, obj: AllColumns | Case | Column | Function | OrderByExpr | Partition | UnsetArgument | ValueIndex | ValueName | Window) => AllColumns | Case | Column | Function | OrderByExpr | Partition | UnsetArgument | ValueIndex | ValueName | Window | null, index: number): AllColumns | Case | Column | Function | OrderByExpr | Partition | UnsetArgument | ValueIndex | ValueName | Window | null;
//# sourceMappingURL=expr-union.d.ts.map