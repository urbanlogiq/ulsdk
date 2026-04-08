import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
import { Role, RoleT } from './role';
export declare class AccessControlList implements flatbuffers.IUnpackableObject<AccessControlListT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): AccessControlList;
    static getRootAsAccessControlList(bb: flatbuffers.ByteBuffer, obj?: AccessControlList): AccessControlList;
    static getSizePrefixedRootAsAccessControlList(bb: flatbuffers.ByteBuffer, obj?: AccessControlList): AccessControlList;
    roles(index: number, obj?: Role): Role | null;
    rolesLength(): number;
    /**
     * The "extends" allows us to chain together ACLs without needing to copy
     * the whole thing. For example, if want to grant Alice access to a file,
     * we would create a new ACL for that file that has Alice in the permissions
     * list but extends the parent directory's ACL to retain all the existing
     * permissions. This can also be used to selectively revoke access (by
     * adding an ACL entry with empty permissions) to an object.
     */
    extends_(obj?: ObjectId): ObjectId | null;
    static startAccessControlList(builder: flatbuffers.Builder): void;
    static addRoles(builder: flatbuffers.Builder, rolesOffset: flatbuffers.Offset): void;
    static createRolesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startRolesVector(builder: flatbuffers.Builder, numElems: number): void;
    static addExtends(builder: flatbuffers.Builder, extends_Offset: flatbuffers.Offset): void;
    static endAccessControlList(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): AccessControlListT;
    unpackTo(_o: AccessControlListT): void;
}
export declare class AccessControlListT implements flatbuffers.IGeneratedObject {
    roles: (RoleT)[];
    extends_: ObjectIdT | null;
    constructor(roles?: (RoleT)[], extends_?: ObjectIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=access-control-list.d.ts.map