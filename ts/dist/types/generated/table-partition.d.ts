import { MvdbPartition } from './mvdb-partition';
import { WorklogPartition } from './worklog-partition';
export declare enum TablePartition {
    NONE = 0,
    MvdbPartition = 1,
    WorklogPartition = 2
}
export declare function unionToTablePartition(type: TablePartition, accessor: (obj: MvdbPartition | WorklogPartition) => MvdbPartition | WorklogPartition | null): MvdbPartition | WorklogPartition | null;
export declare function unionListToTablePartition(type: TablePartition, accessor: (index: number, obj: MvdbPartition | WorklogPartition) => MvdbPartition | WorklogPartition | null, index: number): MvdbPartition | WorklogPartition | null;
//# sourceMappingURL=table-partition.d.ts.map