import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { B2cId, B2cIdT } from './b2c-id';
export declare class Role implements flatbuffers.IUnpackableObject<RoleT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Role;
    static getRootAsRole(bb: flatbuffers.ByteBuffer, obj?: Role): Role;
    static getSizePrefixedRootAsRole(bb: flatbuffers.ByteBuffer, obj?: Role): Role;
    permission(): number;
    principal(obj?: B2cId): B2cId | null;
    static startRole(builder: flatbuffers.Builder): void;
    static addPermission(builder: flatbuffers.Builder, permission: number): void;
    static addPrincipal(builder: flatbuffers.Builder, principalOffset: flatbuffers.Offset): void;
    static endRole(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): RoleT;
    unpackTo(_o: RoleT): void;
}
export declare class RoleT implements flatbuffers.IGeneratedObject {
    permission: number;
    principal: B2cIdT | null;
    constructor(permission?: number, principal?: B2cIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=role.d.ts.map