import { AccessRequest } from './access-request';
import { DriveChange } from './drive-change';
import { JobComplete } from './job-complete';
import { Share } from './share';
export declare enum NotificationUnion {
    NONE = 0,
    Share = 1,
    JobComplete = 2,
    AccessRequest = 3,
    DriveChange = 4
}
export declare function unionToNotificationUnion(type: NotificationUnion, accessor: (obj: AccessRequest | DriveChange | JobComplete | Share) => AccessRequest | DriveChange | JobComplete | Share | null): AccessRequest | DriveChange | JobComplete | Share | null;
export declare function unionListToNotificationUnion(type: NotificationUnion, accessor: (index: number, obj: AccessRequest | DriveChange | JobComplete | Share) => AccessRequest | DriveChange | JobComplete | Share | null, index: number): AccessRequest | DriveChange | JobComplete | Share | null;
//# sourceMappingURL=notification-union.d.ts.map