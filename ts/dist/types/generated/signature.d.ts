import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class Signature implements flatbuffers.IUnpackableObject<SignatureT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Signature;
    static getRootAsSignature(bb: flatbuffers.ByteBuffer, obj?: Signature): Signature;
    static getSizePrefixedRootAsSignature(bb: flatbuffers.ByteBuffer, obj?: Signature): Signature;
    kid(): string | null;
    kid(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    sig(index: number): number | null;
    sigLength(): number;
    sigArray(): Uint8Array | null;
    static startSignature(builder: flatbuffers.Builder): void;
    static addKid(builder: flatbuffers.Builder, kidOffset: flatbuffers.Offset): void;
    static addSig(builder: flatbuffers.Builder, sigOffset: flatbuffers.Offset): void;
    static createSigVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startSigVector(builder: flatbuffers.Builder, numElems: number): void;
    static endSignature(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createSignature(builder: flatbuffers.Builder, kidOffset: flatbuffers.Offset, sigOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): SignatureT;
    unpackTo(_o: SignatureT): void;
}
export declare class SignatureT implements flatbuffers.IGeneratedObject {
    kid: string | Uint8Array | null;
    sig: (number)[];
    constructor(kid?: string | Uint8Array | null, sig?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=signature.d.ts.map