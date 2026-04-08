import { Delete } from './delete';
import { Modify } from './modify';
import { Restore } from './restore';
export declare enum ChangeOp {
    NONE = 0,
    Modify = 1,
    Delete = 2,
    Restore = 3
}
export declare function unionToChangeOp(type: ChangeOp, accessor: (obj: Delete | Modify | Restore) => Delete | Modify | Restore | null): Delete | Modify | Restore | null;
export declare function unionListToChangeOp(type: ChangeOp, accessor: (index: number, obj: Delete | Modify | Restore) => Delete | Modify | Restore | null, index: number): Delete | Modify | Restore | null;
//# sourceMappingURL=change-op.d.ts.map