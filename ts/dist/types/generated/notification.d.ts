import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { AccessRequestT } from './access-request';
import { B2cId, B2cIdT } from './b2c-id';
import { DriveChangeT } from './drive-change';
import { JobCompleteT } from './job-complete';
import { NotificationUnion } from './notification-union';
import { ShareT } from './share';
export declare class Notification implements flatbuffers.IUnpackableObject<NotificationT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Notification;
    static getRootAsNotification(bb: flatbuffers.ByteBuffer, obj?: Notification): Notification;
    static getSizePrefixedRootAsNotification(bb: flatbuffers.ByteBuffer, obj?: Notification): Notification;
    sender(obj?: B2cId): B2cId | null;
    notificationType(): NotificationUnion;
    notification<T extends flatbuffers.Table>(obj: any): any | null;
    static startNotification(builder: flatbuffers.Builder): void;
    static addSender(builder: flatbuffers.Builder, senderOffset: flatbuffers.Offset): void;
    static addNotificationType(builder: flatbuffers.Builder, notificationType: NotificationUnion): void;
    static addNotification(builder: flatbuffers.Builder, notificationOffset: flatbuffers.Offset): void;
    static endNotification(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createNotification(builder: flatbuffers.Builder, senderOffset: flatbuffers.Offset, notificationType: NotificationUnion, notificationOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): NotificationT;
    unpackTo(_o: NotificationT): void;
}
export declare class NotificationT implements flatbuffers.IGeneratedObject {
    sender: B2cIdT | null;
    notificationType: NotificationUnion;
    notification: AccessRequestT | DriveChangeT | JobCompleteT | ShareT | null;
    constructor(sender?: B2cIdT | null, notificationType?: NotificationUnion, notification?: AccessRequestT | DriveChangeT | JobCompleteT | ShareT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=notification.d.ts.map