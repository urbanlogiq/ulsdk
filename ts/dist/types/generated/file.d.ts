import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Chunk, ChunkT } from './chunk';
import { Digest } from './digest';
import { GenericId, GenericIdT } from './generic-id';
import { Sha256T } from './sha256';
import { StorageTier } from './storage-tier';
export declare class File implements flatbuffers.IUnpackableObject<FileT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): File;
    static getRootAsFile(bb: flatbuffers.ByteBuffer, obj?: File): File;
    static getSizePrefixedRootAsFile(bb: flatbuffers.ByteBuffer, obj?: File): File;
    mime(): string | null;
    mime(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    size(): bigint;
    blob(obj?: GenericId): GenericId | null;
    virus(): string | null;
    virus(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    digestType(): Digest;
    digest<T extends flatbuffers.Table>(obj: any): any | null;
    account(): string | null;
    account(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    container(): string | null;
    container(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    chunks(index: number, obj?: Chunk): Chunk | null;
    chunksLength(): number;
    tier(): StorageTier;
    static startFile(builder: flatbuffers.Builder): void;
    static addMime(builder: flatbuffers.Builder, mimeOffset: flatbuffers.Offset): void;
    static addSize(builder: flatbuffers.Builder, size: bigint): void;
    static addBlob(builder: flatbuffers.Builder, blobOffset: flatbuffers.Offset): void;
    static addVirus(builder: flatbuffers.Builder, virusOffset: flatbuffers.Offset): void;
    static addDigestType(builder: flatbuffers.Builder, digestType: Digest): void;
    static addDigest(builder: flatbuffers.Builder, digestOffset: flatbuffers.Offset): void;
    static addAccount(builder: flatbuffers.Builder, accountOffset: flatbuffers.Offset): void;
    static addContainer(builder: flatbuffers.Builder, containerOffset: flatbuffers.Offset): void;
    static addChunks(builder: flatbuffers.Builder, chunksOffset: flatbuffers.Offset): void;
    static createChunksVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startChunksVector(builder: flatbuffers.Builder, numElems: number): void;
    static addTier(builder: flatbuffers.Builder, tier: StorageTier): void;
    static endFile(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): FileT;
    unpackTo(_o: FileT): void;
}
export declare class FileT implements flatbuffers.IGeneratedObject {
    mime: string | Uint8Array | null;
    size: bigint;
    blob: GenericIdT | null;
    virus: string | Uint8Array | null;
    digestType: Digest;
    digest: Sha256T | null;
    account: string | Uint8Array | null;
    container: string | Uint8Array | null;
    chunks: (ChunkT)[];
    tier: StorageTier;
    constructor(mime?: string | Uint8Array | null, size?: bigint, blob?: GenericIdT | null, virus?: string | Uint8Array | null, digestType?: Digest, digest?: Sha256T | null, account?: string | Uint8Array | null, container?: string | Uint8Array | null, chunks?: (ChunkT)[], tier?: StorageTier);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=file.d.ts.map