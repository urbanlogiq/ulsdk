import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
import { RequestStatus } from './request-status';
export declare class AccessRequest implements flatbuffers.IUnpackableObject<AccessRequestT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): AccessRequest;
    static getRootAsAccessRequest(bb: flatbuffers.ByteBuffer, obj?: AccessRequest): AccessRequest;
    static getSizePrefixedRootAsAccessRequest(bb: flatbuffers.ByteBuffer, obj?: AccessRequest): AccessRequest;
    object(obj?: ObjectId): ObjectId | null;
    perms(): number;
    status(): RequestStatus;
    msg(): string | null;
    msg(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    requestedOwnership(): number;
    static startAccessRequest(builder: flatbuffers.Builder): void;
    static addObject(builder: flatbuffers.Builder, objectOffset: flatbuffers.Offset): void;
    static addPerms(builder: flatbuffers.Builder, perms: number): void;
    static addStatus(builder: flatbuffers.Builder, status: RequestStatus): void;
    static addMsg(builder: flatbuffers.Builder, msgOffset: flatbuffers.Offset): void;
    static addRequestedOwnership(builder: flatbuffers.Builder, requestedOwnership: number): void;
    static endAccessRequest(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createAccessRequest(builder: flatbuffers.Builder, objectOffset: flatbuffers.Offset, perms: number, status: RequestStatus, msgOffset: flatbuffers.Offset, requestedOwnership: number): flatbuffers.Offset;
    unpack(): AccessRequestT;
    unpackTo(_o: AccessRequestT): void;
}
export declare class AccessRequestT implements flatbuffers.IGeneratedObject {
    object: ObjectIdT | null;
    perms: number;
    status: RequestStatus;
    msg: string | Uint8Array | null;
    requestedOwnership: number;
    constructor(object?: ObjectIdT | null, perms?: number, status?: RequestStatus, msg?: string | Uint8Array | null, requestedOwnership?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=access-request.d.ts.map