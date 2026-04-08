import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class ShareDetails implements flatbuffers.IUnpackableObject<ShareDetailsT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ShareDetails;
    static getRootAsShareDetails(bb: flatbuffers.ByteBuffer, obj?: ShareDetails): ShareDetails;
    static getSizePrefixedRootAsShareDetails(bb: flatbuffers.ByteBuffer, obj?: ShareDetails): ShareDetails;
    notify(): boolean;
    msg(): string | null;
    msg(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startShareDetails(builder: flatbuffers.Builder): void;
    static addNotify(builder: flatbuffers.Builder, notify: boolean): void;
    static addMsg(builder: flatbuffers.Builder, msgOffset: flatbuffers.Offset): void;
    static endShareDetails(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createShareDetails(builder: flatbuffers.Builder, notify: boolean, msgOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ShareDetailsT;
    unpackTo(_o: ShareDetailsT): void;
}
export declare class ShareDetailsT implements flatbuffers.IGeneratedObject {
    notify: boolean;
    msg: string | Uint8Array | null;
    constructor(notify?: boolean, msg?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=share-details.d.ts.map