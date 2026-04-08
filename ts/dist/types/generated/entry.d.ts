import { Directory } from './directory';
import { File } from './file';
import { ObjectRef } from './object-ref';
export declare enum Entry {
    NONE = 0,
    File = 1,
    Directory = 2,
    ObjectRef = 3
}
export declare function unionToEntry(type: Entry, accessor: (obj: Directory | File | ObjectRef) => Directory | File | ObjectRef | null): Directory | File | ObjectRef | null;
export declare function unionListToEntry(type: Entry, accessor: (index: number, obj: Directory | File | ObjectRef) => Directory | File | ObjectRef | null, index: number): Directory | File | ObjectRef | null;
//# sourceMappingURL=entry.d.ts.map