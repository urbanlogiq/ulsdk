import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { AttributePair, AttributePairT } from './attribute-pair';
import { B2cId, B2cIdT } from './b2c-id';
import { ContentId, ContentIdT } from './content-id';
import { DataCatalogObjectTy } from './data-catalog-object-ty';
export declare class DataCatalogObject implements flatbuffers.IUnpackableObject<DataCatalogObjectT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DataCatalogObject;
    static getRootAsDataCatalogObject(bb: flatbuffers.ByteBuffer, obj?: DataCatalogObject): DataCatalogObject;
    static getSizePrefixedRootAsDataCatalogObject(bb: flatbuffers.ByteBuffer, obj?: DataCatalogObject): DataCatalogObject;
    ty(): DataCatalogObjectTy;
    /**
     * This field is either an embedded flatbuffer containing the actual object
     * content (ie: worklog, schematic, ...) if the Encrypted flag is unset, or
     * an EncryptedObject where the obj field of the EncryptedObject table is
     * the embedded flatbuffer of the object if it is set.
     */
    obj(index: number): number | null;
    objLength(): number;
    objArray(): Uint8Array | null;
    /**
     * Parent nodes of this commit. To handle the cases of multiple parents (ie:
     * in cases of parallel mutation), this field allows multiple IDs to be specified.
     */
    parents(index: number, obj?: ContentId): ContentId | null;
    parentsLength(): number;
    /**
     * User ID of the person committing the change.
     */
    user(obj?: B2cId): B2cId | null;
    /**
     * Optional change log comment
     */
    comment(): string | null;
    comment(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    /**
     * UTC timestamp (in ms) when this change was made.
     */
    time(): bigint;
    tags(index: number): string;
    tags(index: number, optionalEncoding: flatbuffers.Encoding): string | Uint8Array;
    tagsLength(): number;
    flags(): number;
    attributes(index: number, obj?: AttributePair): AttributePair | null;
    attributesLength(): number;
    version(): number;
    /**
     * Default protection mode (see PermissionTy in the permissions module).
     * Purpose is to determine what happens when an object is navigated to
     * (ie: a directory in the drive). Defaults to 0 (ie: no access)
     */
    defaultMode(): number;
    signature(index: number): number | null;
    signatureLength(): number;
    signatureArray(): Uint8Array | null;
    static startDataCatalogObject(builder: flatbuffers.Builder): void;
    static addTy(builder: flatbuffers.Builder, ty: DataCatalogObjectTy): void;
    static addObj(builder: flatbuffers.Builder, objOffset: flatbuffers.Offset): void;
    static createObjVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startObjVector(builder: flatbuffers.Builder, numElems: number): void;
    static addParents(builder: flatbuffers.Builder, parentsOffset: flatbuffers.Offset): void;
    static createParentsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startParentsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addUser(builder: flatbuffers.Builder, userOffset: flatbuffers.Offset): void;
    static addComment(builder: flatbuffers.Builder, commentOffset: flatbuffers.Offset): void;
    static addTime(builder: flatbuffers.Builder, time: bigint): void;
    static addTags(builder: flatbuffers.Builder, tagsOffset: flatbuffers.Offset): void;
    static createTagsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startTagsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addFlags(builder: flatbuffers.Builder, flags: number): void;
    static addAttributes(builder: flatbuffers.Builder, attributesOffset: flatbuffers.Offset): void;
    static createAttributesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startAttributesVector(builder: flatbuffers.Builder, numElems: number): void;
    static addVersion(builder: flatbuffers.Builder, version: number): void;
    static addDefaultMode(builder: flatbuffers.Builder, defaultMode: number): void;
    static addSignature(builder: flatbuffers.Builder, signatureOffset: flatbuffers.Offset): void;
    static createSignatureVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startSignatureVector(builder: flatbuffers.Builder, numElems: number): void;
    static endDataCatalogObject(builder: flatbuffers.Builder): flatbuffers.Offset;
    static finishDataCatalogObjectBuffer(builder: flatbuffers.Builder, offset: flatbuffers.Offset): void;
    static finishSizePrefixedDataCatalogObjectBuffer(builder: flatbuffers.Builder, offset: flatbuffers.Offset): void;
    unpack(): DataCatalogObjectT;
    unpackTo(_o: DataCatalogObjectT): void;
}
export declare class DataCatalogObjectT implements flatbuffers.IGeneratedObject {
    ty: DataCatalogObjectTy;
    obj: (number)[];
    parents: (ContentIdT)[];
    user: B2cIdT | null;
    comment: string | Uint8Array | null;
    time: bigint;
    tags: (string)[];
    flags: number;
    attributes: (AttributePairT)[];
    version: number;
    defaultMode: number;
    signature: (number)[];
    constructor(ty?: DataCatalogObjectTy, obj?: (number)[], parents?: (ContentIdT)[], user?: B2cIdT | null, comment?: string | Uint8Array | null, time?: bigint, tags?: (string)[], flags?: number, attributes?: (AttributePairT)[], version?: number, defaultMode?: number, signature?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=data-catalog-object.d.ts.map