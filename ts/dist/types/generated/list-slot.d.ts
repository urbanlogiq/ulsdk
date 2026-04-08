import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Attr, AttrT } from './attr';
import { B2cId, B2cIdT } from './b2c-id';
import { ListDirectoryT } from './list-directory';
import { ListEntry } from './list-entry';
import { ListFileT } from './list-file';
import { ListObjectT } from './list-object';
import { ObjectId, ObjectIdT } from './object-id';
import { TopLevelDirectoryT } from './top-level-directory';
export declare class ListSlot implements flatbuffers.IUnpackableObject<ListSlotT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ListSlot;
    static getRootAsListSlot(bb: flatbuffers.ByteBuffer, obj?: ListSlot): ListSlot;
    static getSizePrefixedRootAsListSlot(bb: flatbuffers.ByteBuffer, obj?: ListSlot): ListSlot;
    id(obj?: ObjectId): ObjectId | null;
    entryType(): ListEntry;
    entry<T extends flatbuffers.Table>(obj: any): any | null;
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    userPermissions(): number;
    time(): bigint;
    size(): bigint;
    attributes(index: number, obj?: Attr): Attr | null;
    attributesLength(): number;
    lastModifiedBy(obj?: B2cId): B2cId | null;
    static startListSlot(builder: flatbuffers.Builder): void;
    static addId(builder: flatbuffers.Builder, idOffset: flatbuffers.Offset): void;
    static addEntryType(builder: flatbuffers.Builder, entryType: ListEntry): void;
    static addEntry(builder: flatbuffers.Builder, entryOffset: flatbuffers.Offset): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static addUserPermissions(builder: flatbuffers.Builder, userPermissions: number): void;
    static addTime(builder: flatbuffers.Builder, time: bigint): void;
    static addSize(builder: flatbuffers.Builder, size: bigint): void;
    static addAttributes(builder: flatbuffers.Builder, attributesOffset: flatbuffers.Offset): void;
    static createAttributesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startAttributesVector(builder: flatbuffers.Builder, numElems: number): void;
    static addLastModifiedBy(builder: flatbuffers.Builder, lastModifiedByOffset: flatbuffers.Offset): void;
    static endListSlot(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): ListSlotT;
    unpackTo(_o: ListSlotT): void;
}
export declare class ListSlotT implements flatbuffers.IGeneratedObject {
    id: ObjectIdT | null;
    entryType: ListEntry;
    entry: ListDirectoryT | ListFileT | ListObjectT | TopLevelDirectoryT | null;
    name: string | Uint8Array | null;
    userPermissions: number;
    time: bigint;
    size: bigint;
    attributes: (AttrT)[];
    lastModifiedBy: B2cIdT | null;
    constructor(id?: ObjectIdT | null, entryType?: ListEntry, entry?: ListDirectoryT | ListFileT | ListObjectT | TopLevelDirectoryT | null, name?: string | Uint8Array | null, userPermissions?: number, time?: bigint, size?: bigint, attributes?: (AttrT)[], lastModifiedBy?: B2cIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=list-slot.d.ts.map