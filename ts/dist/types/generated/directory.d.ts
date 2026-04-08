import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { B2cId, B2cIdT } from './b2c-id';
import { Slot, SlotT } from './slot';
/**
 * This Directory table holds the entries in the actual directory
 */
export declare class Directory implements flatbuffers.IUnpackableObject<DirectoryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Directory;
    static getRootAsDirectory(bb: flatbuffers.ByteBuffer, obj?: Directory): Directory;
    static getSizePrefixedRootAsDirectory(bb: flatbuffers.ByteBuffer, obj?: Directory): Directory;
    slots(index: number, obj?: Slot): Slot | null;
    slotsLength(): number;
    notifications(index: number, obj?: B2cId): B2cId | null;
    notificationsLength(): number;
    static startDirectory(builder: flatbuffers.Builder): void;
    static addSlots(builder: flatbuffers.Builder, slotsOffset: flatbuffers.Offset): void;
    static createSlotsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startSlotsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addNotifications(builder: flatbuffers.Builder, notificationsOffset: flatbuffers.Offset): void;
    static createNotificationsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startNotificationsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endDirectory(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDirectory(builder: flatbuffers.Builder, slotsOffset: flatbuffers.Offset, notificationsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DirectoryT;
    unpackTo(_o: DirectoryT): void;
}
export declare class DirectoryT implements flatbuffers.IGeneratedObject {
    slots: (SlotT)[];
    notifications: (B2cIdT)[];
    constructor(slots?: (SlotT)[], notifications?: (B2cIdT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=directory.d.ts.map