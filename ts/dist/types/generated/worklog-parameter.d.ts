import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ByteArrayT } from './byte-array';
import { ObjectIdT } from './object-id';
import { ParameterFlagsT } from './parameter-flags';
import { ParameterValue } from './parameter-value';
import { ValueInstanceT } from './value-instance';
export declare class WorklogParameter implements flatbuffers.IUnpackableObject<WorklogParameterT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): WorklogParameter;
    static getRootAsWorklogParameter(bb: flatbuffers.ByteBuffer, obj?: WorklogParameter): WorklogParameter;
    static getSizePrefixedRootAsWorklogParameter(bb: flatbuffers.ByteBuffer, obj?: WorklogParameter): WorklogParameter;
    key(): string | null;
    key(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    valueType(): ParameterValue;
    value<T extends flatbuffers.Table>(obj: any): any | null;
    static startWorklogParameter(builder: flatbuffers.Builder): void;
    static addKey(builder: flatbuffers.Builder, keyOffset: flatbuffers.Offset): void;
    static addValueType(builder: flatbuffers.Builder, valueType: ParameterValue): void;
    static addValue(builder: flatbuffers.Builder, valueOffset: flatbuffers.Offset): void;
    static endWorklogParameter(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createWorklogParameter(builder: flatbuffers.Builder, keyOffset: flatbuffers.Offset, valueType: ParameterValue, valueOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): WorklogParameterT;
    unpackTo(_o: WorklogParameterT): void;
}
export declare class WorklogParameterT implements flatbuffers.IGeneratedObject {
    key: string | Uint8Array | null;
    valueType: ParameterValue;
    value: ByteArrayT | ObjectIdT | ParameterFlagsT | ValueInstanceT | null;
    constructor(key?: string | Uint8Array | null, valueType?: ParameterValue, value?: ByteArrayT | ObjectIdT | ParameterFlagsT | ValueInstanceT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=worklog-parameter.d.ts.map