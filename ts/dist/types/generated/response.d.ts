import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class Response implements flatbuffers.IUnpackableObject<ResponseT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Response;
    static getRootAsResponse(bb: flatbuffers.ByteBuffer, obj?: Response): Response;
    static getSizePrefixedRootAsResponse(bb: flatbuffers.ByteBuffer, obj?: Response): Response;
    msg(): string | null;
    msg(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startResponse(builder: flatbuffers.Builder): void;
    static addMsg(builder: flatbuffers.Builder, msgOffset: flatbuffers.Offset): void;
    static endResponse(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createResponse(builder: flatbuffers.Builder, msgOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ResponseT;
    unpackTo(_o: ResponseT): void;
}
export declare class ResponseT implements flatbuffers.IGeneratedObject {
    msg: string | Uint8Array | null;
    constructor(msg?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=response.d.ts.map