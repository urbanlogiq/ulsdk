import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class CryptHeader implements flatbuffers.IUnpackableObject<CryptHeaderT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): CryptHeader;
    static getRootAsCryptHeader(bb: flatbuffers.ByteBuffer, obj?: CryptHeader): CryptHeader;
    static getSizePrefixedRootAsCryptHeader(bb: flatbuffers.ByteBuffer, obj?: CryptHeader): CryptHeader;
    /**
     * An ID for the key used to encrypt this particular encrypted object.
     */
    kid(): string | null;
    kid(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    nonce(index: number): number | null;
    nonceLength(): number;
    nonceArray(): Uint8Array | null;
    plaintextLen(): number;
    static startCryptHeader(builder: flatbuffers.Builder): void;
    static addKid(builder: flatbuffers.Builder, kidOffset: flatbuffers.Offset): void;
    static addNonce(builder: flatbuffers.Builder, nonceOffset: flatbuffers.Offset): void;
    static createNonceVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startNonceVector(builder: flatbuffers.Builder, numElems: number): void;
    static addPlaintextLen(builder: flatbuffers.Builder, plaintextLen: number): void;
    static endCryptHeader(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createCryptHeader(builder: flatbuffers.Builder, kidOffset: flatbuffers.Offset, nonceOffset: flatbuffers.Offset, plaintextLen: number): flatbuffers.Offset;
    unpack(): CryptHeaderT;
    unpackTo(_o: CryptHeaderT): void;
}
export declare class CryptHeaderT implements flatbuffers.IGeneratedObject {
    kid: string | Uint8Array | null;
    nonce: (number)[];
    plaintextLen: number;
    constructor(kid?: string | Uint8Array | null, nonce?: (number)[], plaintextLen?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=crypt-header.d.ts.map