import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { DriveAction } from './drive-action';
import { ObjectId, ObjectIdT } from './object-id';
export declare class DriveChange implements flatbuffers.IUnpackableObject<DriveChangeT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DriveChange;
    static getRootAsDriveChange(bb: flatbuffers.ByteBuffer, obj?: DriveChange): DriveChange;
    static getSizePrefixedRootAsDriveChange(bb: flatbuffers.ByteBuffer, obj?: DriveChange): DriveChange;
    root(obj?: ObjectId): ObjectId | null;
    object(obj?: ObjectId): ObjectId | null;
    action(): DriveAction;
    static startDriveChange(builder: flatbuffers.Builder): void;
    static addRoot(builder: flatbuffers.Builder, rootOffset: flatbuffers.Offset): void;
    static addObject(builder: flatbuffers.Builder, objectOffset: flatbuffers.Offset): void;
    static addAction(builder: flatbuffers.Builder, action: DriveAction): void;
    static endDriveChange(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): DriveChangeT;
    unpackTo(_o: DriveChangeT): void;
}
export declare class DriveChangeT implements flatbuffers.IGeneratedObject {
    root: ObjectIdT | null;
    object: ObjectIdT | null;
    action: DriveAction;
    constructor(root?: ObjectIdT | null, object?: ObjectIdT | null, action?: DriveAction);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=drive-change.d.ts.map