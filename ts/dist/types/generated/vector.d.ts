import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { NullableUint, NullableUintT } from './nullable-uint';
import { ObjectId, ObjectIdT } from './object-id';
export declare class Vector implements flatbuffers.IUnpackableObject<VectorT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Vector;
    static getRootAsVector(bb: flatbuffers.ByteBuffer, obj?: Vector): Vector;
    static getSizePrefixedRootAsVector(bb: flatbuffers.ByteBuffer, obj?: Vector): Vector;
    query(): string | null;
    query(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    limit(obj?: NullableUint): NullableUint | null;
    /**
     * List of vectordbs to query. If this is empty, query all available vectordbs.
     */
    ids(index: number, obj?: ObjectId): ObjectId | null;
    idsLength(): number;
    /**
     * Optionally limit the results to those with a distance value less than
     * max_distance. We treat max_distance=0 as no limit.
     */
    maxDistance(): number;
    static startVector(builder: flatbuffers.Builder): void;
    static addQuery(builder: flatbuffers.Builder, queryOffset: flatbuffers.Offset): void;
    static addLimit(builder: flatbuffers.Builder, limitOffset: flatbuffers.Offset): void;
    static addIds(builder: flatbuffers.Builder, idsOffset: flatbuffers.Offset): void;
    static createIdsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startIdsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addMaxDistance(builder: flatbuffers.Builder, maxDistance: number): void;
    static endVector(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): VectorT;
    unpackTo(_o: VectorT): void;
}
export declare class VectorT implements flatbuffers.IGeneratedObject {
    query: string | Uint8Array | null;
    limit: NullableUintT | null;
    ids: (ObjectIdT)[];
    maxDistance: number;
    constructor(query?: string | Uint8Array | null, limit?: NullableUintT | null, ids?: (ObjectIdT)[], maxDistance?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=vector.d.ts.map