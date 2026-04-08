import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
/**
 * Body parameter for PUT drive/<object>
 */
export declare class NewLink implements flatbuffers.IUnpackableObject<NewLinkT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NewLink;
    static getRootAsNewLink(bb: flatbuffers.ByteBuffer, obj?: NewLink): NewLink;
    static getSizePrefixedRootAsNewLink(bb: flatbuffers.ByteBuffer, obj?: NewLink): NewLink;
    obj(obj?: ObjectId): ObjectId | null;
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startNewLink(builder: flatbuffers.Builder): void;
    static addObj(builder: flatbuffers.Builder, objOffset: flatbuffers.Offset): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static endNewLink(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createNewLink(builder: flatbuffers.Builder, objOffset: flatbuffers.Offset, nameOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): NewLinkT;
    unpackTo(_o: NewLinkT): void;
}
export declare class NewLinkT implements flatbuffers.IGeneratedObject {
    obj: ObjectIdT | null;
    name: string | Uint8Array | null;
    constructor(obj?: ObjectIdT | null, name?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=new-link.d.ts.map