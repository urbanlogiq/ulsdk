import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
export declare class MoveRequest implements flatbuffers.IUnpackableObject<MoveRequestT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): MoveRequest;
    static getRootAsMoveRequest(bb: flatbuffers.ByteBuffer, obj?: MoveRequest): MoveRequest;
    static getSizePrefixedRootAsMoveRequest(bb: flatbuffers.ByteBuffer, obj?: MoveRequest): MoveRequest;
    entry(obj?: ObjectId): ObjectId | null;
    destRoot(obj?: ObjectId): ObjectId | null;
    destName(): string | null;
    destName(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    overwrite(): boolean;
    static startMoveRequest(builder: flatbuffers.Builder): void;
    static addEntry(builder: flatbuffers.Builder, entryOffset: flatbuffers.Offset): void;
    static addDestRoot(builder: flatbuffers.Builder, destRootOffset: flatbuffers.Offset): void;
    static addDestName(builder: flatbuffers.Builder, destNameOffset: flatbuffers.Offset): void;
    static addOverwrite(builder: flatbuffers.Builder, overwrite: boolean): void;
    static endMoveRequest(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): MoveRequestT;
    unpackTo(_o: MoveRequestT): void;
}
export declare class MoveRequestT implements flatbuffers.IGeneratedObject {
    entry: ObjectIdT | null;
    destRoot: ObjectIdT | null;
    destName: string | Uint8Array | null;
    overwrite: boolean;
    constructor(entry?: ObjectIdT | null, destRoot?: ObjectIdT | null, destName?: string | Uint8Array | null, overwrite?: boolean);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=move-request.d.ts.map