import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { DirectoryT } from './directory';
import { Entry } from './entry';
import { FileT } from './file';
import { ObjectId, ObjectIdT } from './object-id';
import { ObjectRefT } from './object-ref';
export declare class DirectoryEntry implements flatbuffers.IUnpackableObject<DirectoryEntryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DirectoryEntry;
    static getRootAsDirectoryEntry(bb: flatbuffers.ByteBuffer, obj?: DirectoryEntry): DirectoryEntry;
    static getSizePrefixedRootAsDirectoryEntry(bb: flatbuffers.ByteBuffer, obj?: DirectoryEntry): DirectoryEntry;
    entryType(): Entry;
    entry<T extends flatbuffers.Table>(obj: any): any | null;
    parent(obj?: ObjectId): ObjectId | null;
    static startDirectoryEntry(builder: flatbuffers.Builder): void;
    static addEntryType(builder: flatbuffers.Builder, entryType: Entry): void;
    static addEntry(builder: flatbuffers.Builder, entryOffset: flatbuffers.Offset): void;
    static addParent(builder: flatbuffers.Builder, parentOffset: flatbuffers.Offset): void;
    static endDirectoryEntry(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): DirectoryEntryT;
    unpackTo(_o: DirectoryEntryT): void;
}
export declare class DirectoryEntryT implements flatbuffers.IGeneratedObject {
    entryType: Entry;
    entry: DirectoryT | FileT | ObjectRefT | null;
    parent: ObjectIdT | null;
    constructor(entryType?: Entry, entry?: DirectoryT | FileT | ObjectRefT | null, parent?: ObjectIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=directory-entry.d.ts.map