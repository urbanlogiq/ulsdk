import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Attr, AttrT } from './attr';
import { EntryTy } from './entry-ty';
import { ObjectId, ObjectIdT } from './object-id';
export declare class Slot implements flatbuffers.IUnpackableObject<SlotT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Slot;
    static getRootAsSlot(bb: flatbuffers.ByteBuffer, obj?: Slot): Slot;
    static getSizePrefixedRootAsSlot(bb: flatbuffers.ByteBuffer, obj?: Slot): Slot;
    id(obj?: ObjectId): ObjectId | null;
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    ty(): EntryTy;
    attributes(index: number, obj?: Attr): Attr | null;
    attributesLength(): number;
    static startSlot(builder: flatbuffers.Builder): void;
    static addId(builder: flatbuffers.Builder, idOffset: flatbuffers.Offset): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static addTy(builder: flatbuffers.Builder, ty: EntryTy): void;
    static addAttributes(builder: flatbuffers.Builder, attributesOffset: flatbuffers.Offset): void;
    static createAttributesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startAttributesVector(builder: flatbuffers.Builder, numElems: number): void;
    static endSlot(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createSlot(builder: flatbuffers.Builder, idOffset: flatbuffers.Offset, nameOffset: flatbuffers.Offset, ty: EntryTy, attributesOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): SlotT;
    unpackTo(_o: SlotT): void;
}
export declare class SlotT implements flatbuffers.IGeneratedObject {
    id: ObjectIdT | null;
    name: string | Uint8Array | null;
    ty: EntryTy;
    attributes: (AttrT)[];
    constructor(id?: ObjectIdT | null, name?: string | Uint8Array | null, ty?: EntryTy, attributes?: (AttrT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=slot.d.ts.map