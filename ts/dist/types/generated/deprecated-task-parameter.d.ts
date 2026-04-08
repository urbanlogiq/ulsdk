import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
export declare class DeprecatedTaskParameter implements flatbuffers.IUnpackableObject<DeprecatedTaskParameterT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DeprecatedTaskParameter;
    static getRootAsDeprecatedTaskParameter(bb: flatbuffers.ByteBuffer, obj?: DeprecatedTaskParameter): DeprecatedTaskParameter;
    static getSizePrefixedRootAsDeprecatedTaskParameter(bb: flatbuffers.ByteBuffer, obj?: DeprecatedTaskParameter): DeprecatedTaskParameter;
    key(): string | null;
    key(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    value(index: number): number | null;
    valueLength(): number;
    valueArray(): Uint8Array | null;
    obj(obj?: ObjectId): ObjectId | null;
    flags(): bigint;
    static startDeprecatedTaskParameter(builder: flatbuffers.Builder): void;
    static addKey(builder: flatbuffers.Builder, keyOffset: flatbuffers.Offset): void;
    static addValue(builder: flatbuffers.Builder, valueOffset: flatbuffers.Offset): void;
    static createValueVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startValueVector(builder: flatbuffers.Builder, numElems: number): void;
    static addObj(builder: flatbuffers.Builder, objOffset: flatbuffers.Offset): void;
    static addFlags(builder: flatbuffers.Builder, flags: bigint): void;
    static endDeprecatedTaskParameter(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): DeprecatedTaskParameterT;
    unpackTo(_o: DeprecatedTaskParameterT): void;
}
export declare class DeprecatedTaskParameterT implements flatbuffers.IGeneratedObject {
    key: string | Uint8Array | null;
    value: (number)[];
    obj: ObjectIdT | null;
    flags: bigint;
    constructor(key?: string | Uint8Array | null, value?: (number)[], obj?: ObjectIdT | null, flags?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=deprecated-task-parameter.d.ts.map