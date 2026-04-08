import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { EmbeddedTableT } from './embedded-table';
import { ObjectIdT } from './object-id';
import { TaskParameterValue } from './task-parameter-value';
import { ValueInstanceT } from './value-instance';
export declare class TaskParameter implements flatbuffers.IUnpackableObject<TaskParameterT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): TaskParameter;
    static getRootAsTaskParameter(bb: flatbuffers.ByteBuffer, obj?: TaskParameter): TaskParameter;
    static getSizePrefixedRootAsTaskParameter(bb: flatbuffers.ByteBuffer, obj?: TaskParameter): TaskParameter;
    key(): string | null;
    key(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    valueType(): TaskParameterValue;
    value<T extends flatbuffers.Table>(obj: any): any | null;
    static startTaskParameter(builder: flatbuffers.Builder): void;
    static addKey(builder: flatbuffers.Builder, keyOffset: flatbuffers.Offset): void;
    static addValueType(builder: flatbuffers.Builder, valueType: TaskParameterValue): void;
    static addValue(builder: flatbuffers.Builder, valueOffset: flatbuffers.Offset): void;
    static endTaskParameter(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createTaskParameter(builder: flatbuffers.Builder, keyOffset: flatbuffers.Offset, valueType: TaskParameterValue, valueOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): TaskParameterT;
    unpackTo(_o: TaskParameterT): void;
}
export declare class TaskParameterT implements flatbuffers.IGeneratedObject {
    key: string | Uint8Array | null;
    valueType: TaskParameterValue;
    value: EmbeddedTableT | ObjectIdT | ValueInstanceT | null;
    constructor(key?: string | Uint8Array | null, valueType?: TaskParameterValue, value?: EmbeddedTableT | ObjectIdT | ValueInstanceT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=task-parameter.d.ts.map