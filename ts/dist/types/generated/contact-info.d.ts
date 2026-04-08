import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class ContactInfo implements flatbuffers.IUnpackableObject<ContactInfoT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ContactInfo;
    static getRootAsContactInfo(bb: flatbuffers.ByteBuffer, obj?: ContactInfo): ContactInfo;
    static getSizePrefixedRootAsContactInfo(bb: flatbuffers.ByteBuffer, obj?: ContactInfo): ContactInfo;
    email(): string | null;
    email(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    url(): string | null;
    url(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    phone(): string | null;
    phone(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    address(): string | null;
    address(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startContactInfo(builder: flatbuffers.Builder): void;
    static addEmail(builder: flatbuffers.Builder, emailOffset: flatbuffers.Offset): void;
    static addUrl(builder: flatbuffers.Builder, urlOffset: flatbuffers.Offset): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static addPhone(builder: flatbuffers.Builder, phoneOffset: flatbuffers.Offset): void;
    static addAddress(builder: flatbuffers.Builder, addressOffset: flatbuffers.Offset): void;
    static endContactInfo(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createContactInfo(builder: flatbuffers.Builder, emailOffset: flatbuffers.Offset, urlOffset: flatbuffers.Offset, nameOffset: flatbuffers.Offset, phoneOffset: flatbuffers.Offset, addressOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ContactInfoT;
    unpackTo(_o: ContactInfoT): void;
}
export declare class ContactInfoT implements flatbuffers.IGeneratedObject {
    email: string | Uint8Array | null;
    url: string | Uint8Array | null;
    name: string | Uint8Array | null;
    phone: string | Uint8Array | null;
    address: string | Uint8Array | null;
    constructor(email?: string | Uint8Array | null, url?: string | Uint8Array | null, name?: string | Uint8Array | null, phone?: string | Uint8Array | null, address?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=contact-info.d.ts.map