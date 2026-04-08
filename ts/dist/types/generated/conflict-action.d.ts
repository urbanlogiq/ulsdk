import { DoNothing } from './do-nothing';
import { DoUpdate } from './do-update';
import { InsertConflicting } from './insert-conflicting';
export declare enum ConflictAction {
    NONE = 0,
    InsertConflicting = 1,
    DoNothing = 2,
    DoUpdate = 3
}
export declare function unionToConflictAction(type: ConflictAction, accessor: (obj: DoNothing | DoUpdate | InsertConflicting) => DoNothing | DoUpdate | InsertConflicting | null): DoNothing | DoUpdate | InsertConflicting | null;
export declare function unionListToConflictAction(type: ConflictAction, accessor: (index: number, obj: DoNothing | DoUpdate | InsertConflicting) => DoNothing | DoUpdate | InsertConflicting | null, index: number): DoNothing | DoUpdate | InsertConflicting | null;
//# sourceMappingURL=conflict-action.d.ts.map