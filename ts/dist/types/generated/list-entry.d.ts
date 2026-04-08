import { ListDirectory } from './list-directory';
import { ListFile } from './list-file';
import { ListObject } from './list-object';
import { TopLevelDirectory } from './top-level-directory';
export declare enum ListEntry {
    NONE = 0,
    ListFile = 1,
    ListDirectory = 2,
    ListObject = 3,
    TopLevelDirectory = 4
}
export declare function unionToListEntry(type: ListEntry, accessor: (obj: ListDirectory | ListFile | ListObject | TopLevelDirectory) => ListDirectory | ListFile | ListObject | TopLevelDirectory | null): ListDirectory | ListFile | ListObject | TopLevelDirectory | null;
export declare function unionListToListEntry(type: ListEntry, accessor: (index: number, obj: ListDirectory | ListFile | ListObject | TopLevelDirectory) => ListDirectory | ListFile | ListObject | TopLevelDirectory | null, index: number): ListDirectory | ListFile | ListObject | TopLevelDirectory | null;
//# sourceMappingURL=list-entry.d.ts.map