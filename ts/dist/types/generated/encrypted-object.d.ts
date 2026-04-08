import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { CryptHeader, CryptHeaderT } from './crypt-header';
export declare class EncryptedObject implements flatbuffers.IUnpackableObject<EncryptedObjectT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): EncryptedObject;
    static getRootAsEncryptedObject(bb: flatbuffers.ByteBuffer, obj?: EncryptedObject): EncryptedObject;
    static getSizePrefixedRootAsEncryptedObject(bb: flatbuffers.ByteBuffer, obj?: EncryptedObject): EncryptedObject;
    header(obj?: CryptHeader): CryptHeader | null;
    obj(index: number): number | null;
    objLength(): number;
    objArray(): Uint8Array | null;
    static startEncryptedObject(builder: flatbuffers.Builder): void;
    static addHeader(builder: flatbuffers.Builder, headerOffset: flatbuffers.Offset): void;
    static addObj(builder: flatbuffers.Builder, objOffset: flatbuffers.Offset): void;
    static createObjVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startObjVector(builder: flatbuffers.Builder, numElems: number): void;
    static endEncryptedObject(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createEncryptedObject(builder: flatbuffers.Builder, headerOffset: flatbuffers.Offset, objOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): EncryptedObjectT;
    unpackTo(_o: EncryptedObjectT): void;
}
export declare class EncryptedObjectT implements flatbuffers.IGeneratedObject {
    header: CryptHeaderT | null;
    obj: (number)[];
    constructor(header?: CryptHeaderT | null, obj?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=encrypted-object.d.ts.map