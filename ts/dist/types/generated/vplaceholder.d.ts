import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ValueTy } from './value-ty';
export declare class VPlaceholder implements flatbuffers.IUnpackableObject<VPlaceholderT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): VPlaceholder;
    static getRootAsVPlaceholder(bb: flatbuffers.ByteBuffer, obj?: VPlaceholder): VPlaceholder;
    static getSizePrefixedRootAsVPlaceholder(bb: flatbuffers.ByteBuffer, obj?: VPlaceholder): VPlaceholder;
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    ty(): ValueTy;
    static startVPlaceholder(builder: flatbuffers.Builder): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static addTy(builder: flatbuffers.Builder, ty: ValueTy): void;
    static endVPlaceholder(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createVPlaceholder(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset, ty: ValueTy): flatbuffers.Offset;
    unpack(): VPlaceholderT;
    unpackTo(_o: VPlaceholderT): void;
}
export declare class VPlaceholderT implements flatbuffers.IGeneratedObject {
    name: string | Uint8Array | null;
    ty: ValueTy;
    constructor(name?: string | Uint8Array | null, ty?: ValueTy);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vplaceholder.d.ts.map