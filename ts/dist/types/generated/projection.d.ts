import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Predicate } from './predicate';
export declare class Projection implements flatbuffers.IUnpackableObject<ProjectionT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Projection;
    static getRootAsProjection(bb: flatbuffers.ByteBuffer, obj?: Projection): Projection;
    static getSizePrefixedRootAsProjection(bb: flatbuffers.ByteBuffer, obj?: Projection): Projection;
    predicate(): Predicate;
    alias(): string | null;
    alias(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startProjection(builder: flatbuffers.Builder): void;
    static addPredicate(builder: flatbuffers.Builder, predicate: Predicate): void;
    static addAlias(builder: flatbuffers.Builder, aliasOffset: flatbuffers.Offset): void;
    static endProjection(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createProjection(builder: flatbuffers.Builder, predicate: Predicate, aliasOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ProjectionT;
    unpackTo(_o: ProjectionT): void;
}
export declare class ProjectionT implements flatbuffers.IGeneratedObject {
    predicate: Predicate;
    alias: string | Uint8Array | null;
    constructor(predicate?: Predicate, alias?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=projection.d.ts.map