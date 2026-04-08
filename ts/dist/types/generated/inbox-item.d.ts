import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
import { ReadStatus } from './read-status';
export declare class InboxItem implements flatbuffers.IUnpackableObject<InboxItemT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): InboxItem;
    static getRootAsInboxItem(bb: flatbuffers.ByteBuffer, obj?: InboxItem): InboxItem;
    static getSizePrefixedRootAsInboxItem(bb: flatbuffers.ByteBuffer, obj?: InboxItem): InboxItem;
    notification(obj?: ObjectId): ObjectId | null;
    status(): ReadStatus;
    time(): bigint;
    static startInboxItem(builder: flatbuffers.Builder): void;
    static addNotification(builder: flatbuffers.Builder, notificationOffset: flatbuffers.Offset): void;
    static addStatus(builder: flatbuffers.Builder, status: ReadStatus): void;
    static addTime(builder: flatbuffers.Builder, time: bigint): void;
    static endInboxItem(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createInboxItem(builder: flatbuffers.Builder, notificationOffset: flatbuffers.Offset, status: ReadStatus, time: bigint): flatbuffers.Offset;
    unpack(): InboxItemT;
    unpackTo(_o: InboxItemT): void;
}
export declare class InboxItemT implements flatbuffers.IGeneratedObject {
    notification: ObjectIdT | null;
    status: ReadStatus;
    time: bigint;
    constructor(notification?: ObjectIdT | null, status?: ReadStatus, time?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=inbox-item.d.ts.map