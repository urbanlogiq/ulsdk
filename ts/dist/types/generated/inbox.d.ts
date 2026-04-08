import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { InboxItem, InboxItemT } from './inbox-item';
export declare class Inbox implements flatbuffers.IUnpackableObject<InboxT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Inbox;
    static getRootAsInbox(bb: flatbuffers.ByteBuffer, obj?: Inbox): Inbox;
    static getSizePrefixedRootAsInbox(bb: flatbuffers.ByteBuffer, obj?: Inbox): Inbox;
    items(index: number, obj?: InboxItem): InboxItem | null;
    itemsLength(): number;
    static startInbox(builder: flatbuffers.Builder): void;
    static addItems(builder: flatbuffers.Builder, itemsOffset: flatbuffers.Offset): void;
    static createItemsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startItemsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endInbox(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createInbox(builder: flatbuffers.Builder, itemsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): InboxT;
    unpackTo(_o: InboxT): void;
}
export declare class InboxT implements flatbuffers.IGeneratedObject {
    items: (InboxItemT)[];
    constructor(items?: (InboxItemT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=inbox.d.ts.map