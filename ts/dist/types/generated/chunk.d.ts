import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Digest } from './digest';
import { GenericId, GenericIdT } from './generic-id';
import { Sha256T } from './sha256';
export declare class Chunk implements flatbuffers.IUnpackableObject<ChunkT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Chunk;
    static getRootAsChunk(bb: flatbuffers.ByteBuffer, obj?: Chunk): Chunk;
    static getSizePrefixedRootAsChunk(bb: flatbuffers.ByteBuffer, obj?: Chunk): Chunk;
    blob(obj?: GenericId): GenericId | null;
    digestType(): Digest;
    digest<T extends flatbuffers.Table>(obj: any): any | null;
    size(): bigint;
    static startChunk(builder: flatbuffers.Builder): void;
    static addBlob(builder: flatbuffers.Builder, blobOffset: flatbuffers.Offset): void;
    static addDigestType(builder: flatbuffers.Builder, digestType: Digest): void;
    static addDigest(builder: flatbuffers.Builder, digestOffset: flatbuffers.Offset): void;
    static addSize(builder: flatbuffers.Builder, size: bigint): void;
    static endChunk(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createChunk(builder: flatbuffers.Builder, blobOffset: flatbuffers.Offset, digestType: Digest, digestOffset: flatbuffers.Offset, size: bigint): flatbuffers.Offset;
    unpack(): ChunkT;
    unpackTo(_o: ChunkT): void;
}
export declare class ChunkT implements flatbuffers.IGeneratedObject {
    blob: GenericIdT | null;
    digestType: Digest;
    digest: Sha256T | null;
    size: bigint;
    constructor(blob?: GenericIdT | null, digestType?: Digest, digest?: Sha256T | null, size?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=chunk.d.ts.map