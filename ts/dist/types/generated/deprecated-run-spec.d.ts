import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { DeprecatedTaskParameter, DeprecatedTaskParameterT } from './deprecated-task-parameter';
import { ObjectId, ObjectIdT } from './object-id';
import { ParamIndices, ParamIndicesT } from './param-indices';
export declare class DeprecatedRunSpec implements flatbuffers.IUnpackableObject<DeprecatedRunSpecT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DeprecatedRunSpec;
    static getRootAsDeprecatedRunSpec(bb: flatbuffers.ByteBuffer, obj?: DeprecatedRunSpec): DeprecatedRunSpec;
    static getSizePrefixedRootAsDeprecatedRunSpec(bb: flatbuffers.ByteBuffer, obj?: DeprecatedRunSpec): DeprecatedRunSpec;
    persist(): boolean;
    schematic(obj?: ObjectId): ObjectId | null;
    paramIndices(index: number, obj?: ParamIndices): ParamIndices | null;
    paramIndicesLength(): number;
    params(index: number, obj?: DeprecatedTaskParameter): DeprecatedTaskParameter | null;
    paramsLength(): number;
    static startDeprecatedRunSpec(builder: flatbuffers.Builder): void;
    static addPersist(builder: flatbuffers.Builder, persist: boolean): void;
    static addSchematic(builder: flatbuffers.Builder, schematicOffset: flatbuffers.Offset): void;
    static addParamIndices(builder: flatbuffers.Builder, paramIndicesOffset: flatbuffers.Offset): void;
    static createParamIndicesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startParamIndicesVector(builder: flatbuffers.Builder, numElems: number): void;
    static addParams(builder: flatbuffers.Builder, paramsOffset: flatbuffers.Offset): void;
    static createParamsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startParamsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endDeprecatedRunSpec(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): DeprecatedRunSpecT;
    unpackTo(_o: DeprecatedRunSpecT): void;
}
export declare class DeprecatedRunSpecT implements flatbuffers.IGeneratedObject {
    persist: boolean;
    schematic: ObjectIdT | null;
    paramIndices: (ParamIndicesT)[];
    params: (DeprecatedTaskParameterT)[];
    constructor(persist?: boolean, schematic?: ObjectIdT | null, paramIndices?: (ParamIndicesT)[], params?: (DeprecatedTaskParameterT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=deprecated-run-spec.d.ts.map