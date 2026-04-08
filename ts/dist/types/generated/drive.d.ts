import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
export declare class Drive implements flatbuffers.IUnpackableObject<DriveT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Drive;
    static getRootAsDrive(bb: flatbuffers.ByteBuffer, obj?: Drive): Drive;
    static getSizePrefixedRootAsDrive(bb: flatbuffers.ByteBuffer, obj?: Drive): Drive;
    root(obj?: ObjectId): ObjectId | null;
    path(): string | null;
    path(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startDrive(builder: flatbuffers.Builder): void;
    static addRoot(builder: flatbuffers.Builder, rootOffset: flatbuffers.Offset): void;
    static addPath(builder: flatbuffers.Builder, pathOffset: flatbuffers.Offset): void;
    static endDrive(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDrive(builder: flatbuffers.Builder, rootOffset: flatbuffers.Offset, pathOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DriveT;
    unpackTo(_o: DriveT): void;
}
export declare class DriveT implements flatbuffers.IGeneratedObject {
    root: ObjectIdT | null;
    path: string | Uint8Array | null;
    constructor(root?: ObjectIdT | null, path?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=drive.d.ts.map