import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { JoinTy } from './join-ty';
export declare class Join implements flatbuffers.IUnpackableObject<JoinT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Join;
    static getRootAsJoin(bb: flatbuffers.ByteBuffer, obj?: Join): Join;
    static getSizePrefixedRootAsJoin(bb: flatbuffers.ByteBuffer, obj?: Join): Join;
    srcIdx(): number;
    destIdx(): number;
    srcCol(): string | null;
    srcCol(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    destCol(): string | null;
    destCol(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    ty(): JoinTy;
    static startJoin(builder: flatbuffers.Builder): void;
    static addSrcIdx(builder: flatbuffers.Builder, srcIdx: number): void;
    static addDestIdx(builder: flatbuffers.Builder, destIdx: number): void;
    static addSrcCol(builder: flatbuffers.Builder, srcColOffset: flatbuffers.Offset): void;
    static addDestCol(builder: flatbuffers.Builder, destColOffset: flatbuffers.Offset): void;
    static addTy(builder: flatbuffers.Builder, ty: JoinTy): void;
    static endJoin(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createJoin(builder: flatbuffers.Builder, srcIdx: number, destIdx: number, srcColOffset: flatbuffers.Offset, destColOffset: flatbuffers.Offset, ty: JoinTy): flatbuffers.Offset;
    unpack(): JoinT;
    unpackTo(_o: JoinT): void;
}
export declare class JoinT implements flatbuffers.IGeneratedObject {
    srcIdx: number;
    destIdx: number;
    srcCol: string | Uint8Array | null;
    destCol: string | Uint8Array | null;
    ty: JoinTy;
    constructor(srcIdx?: number, destIdx?: number, srcCol?: string | Uint8Array | null, destCol?: string | Uint8Array | null, ty?: JoinTy);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=join.d.ts.map