import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ListSlot, ListSlotT } from './list-slot';
export declare class DirectoryList implements flatbuffers.IUnpackableObject<DirectoryListT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DirectoryList;
    static getRootAsDirectoryList(bb: flatbuffers.ByteBuffer, obj?: DirectoryList): DirectoryList;
    static getSizePrefixedRootAsDirectoryList(bb: flatbuffers.ByteBuffer, obj?: DirectoryList): DirectoryList;
    slots(index: number, obj?: ListSlot): ListSlot | null;
    slotsLength(): number;
    static startDirectoryList(builder: flatbuffers.Builder): void;
    static addSlots(builder: flatbuffers.Builder, slotsOffset: flatbuffers.Offset): void;
    static createSlotsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startSlotsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endDirectoryList(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDirectoryList(builder: flatbuffers.Builder, slotsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DirectoryListT;
    unpackTo(_o: DirectoryListT): void;
}
export declare class DirectoryListT implements flatbuffers.IGeneratedObject {
    slots: (ListSlotT)[];
    constructor(slots?: (ListSlotT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=directory-list.d.ts.map