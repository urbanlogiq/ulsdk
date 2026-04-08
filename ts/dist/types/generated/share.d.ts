import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
import { PermissionTy } from './permission-ty';
export declare class Share implements flatbuffers.IUnpackableObject<ShareT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Share;
    static getRootAsShare(bb: flatbuffers.ByteBuffer, obj?: Share): Share;
    static getSizePrefixedRootAsShare(bb: flatbuffers.ByteBuffer, obj?: Share): Share;
    object(obj?: ObjectId): ObjectId | null;
    dest(): string | null;
    dest(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    msg(): string | null;
    msg(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    oldPerms(): PermissionTy;
    newPerms(): PermissionTy;
    static startShare(builder: flatbuffers.Builder): void;
    static addObject(builder: flatbuffers.Builder, objectOffset: flatbuffers.Offset): void;
    static addDest(builder: flatbuffers.Builder, destOffset: flatbuffers.Offset): void;
    static addMsg(builder: flatbuffers.Builder, msgOffset: flatbuffers.Offset): void;
    static addOldPerms(builder: flatbuffers.Builder, oldPerms: PermissionTy): void;
    static addNewPerms(builder: flatbuffers.Builder, newPerms: PermissionTy): void;
    static endShare(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createShare(builder: flatbuffers.Builder, objectOffset: flatbuffers.Offset, destOffset: flatbuffers.Offset, msgOffset: flatbuffers.Offset, oldPerms: PermissionTy, newPerms: PermissionTy): flatbuffers.Offset;
    unpack(): ShareT;
    unpackTo(_o: ShareT): void;
}
export declare class ShareT implements flatbuffers.IGeneratedObject {
    object: ObjectIdT | null;
    dest: string | Uint8Array | null;
    msg: string | Uint8Array | null;
    oldPerms: PermissionTy;
    newPerms: PermissionTy;
    constructor(object?: ObjectIdT | null, dest?: string | Uint8Array | null, msg?: string | Uint8Array | null, oldPerms?: PermissionTy, newPerms?: PermissionTy);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=share.d.ts.map