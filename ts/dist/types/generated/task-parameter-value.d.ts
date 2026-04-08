import { EmbeddedTable } from './embedded-table';
import { ObjectId } from './object-id';
import { ValueInstance } from './value-instance';
export declare enum TaskParameterValue {
    NONE = 0,
    ObjectId = 1,
    EmbeddedTable = 2,
    ValueInstance = 3
}
export declare function unionToTaskParameterValue(type: TaskParameterValue, accessor: (obj: EmbeddedTable | ObjectId | ValueInstance) => EmbeddedTable | ObjectId | ValueInstance | null): EmbeddedTable | ObjectId | ValueInstance | null;
export declare function unionListToTaskParameterValue(type: TaskParameterValue, accessor: (index: number, obj: EmbeddedTable | ObjectId | ValueInstance) => EmbeddedTable | ObjectId | ValueInstance | null, index: number): EmbeddedTable | ObjectId | ValueInstance | null;
//# sourceMappingURL=task-parameter-value.d.ts.map