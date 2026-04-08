import { Append } from './append';
import { RestoreRow } from './restore-row';
import { RmRow } from './rm-row';
import { Set } from './set';
/**
 * Table Ops are used to modify the contents of a table.
 */
export declare enum Op {
    NONE = 0,
    Set = 1,
    RmRow = 2,
    RestoreRow = 3,
    Append = 4
}
export declare function unionToOp(type: Op, accessor: (obj: Append | RestoreRow | RmRow | Set) => Append | RestoreRow | RmRow | Set | null): Append | RestoreRow | RmRow | Set | null;
export declare function unionListToOp(type: Op, accessor: (index: number, obj: Append | RestoreRow | RmRow | Set) => Append | RestoreRow | RmRow | Set | null, index: number): Append | RestoreRow | RmRow | Set | null;
//# sourceMappingURL=op.d.ts.map