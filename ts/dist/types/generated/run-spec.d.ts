import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Attr, AttrT } from './attr';
import { ObjectId, ObjectIdT } from './object-id';
import { ParamIndices, ParamIndicesT } from './param-indices';
import { TaskParameter, TaskParameterT } from './task-parameter';
import { TaskPriority } from './task-priority';
/**
 * A RunSpec is the data required in order to kickstart a schematic job.
 * It includes the ID of the schematic to run along with the parameters.
 * The param_indices list must be *exactly* as long as the nodes list in
 * the Schematic. Each entry in the param_indices list is itself a list
 * that points to all the parameters in the params array. This lets
 * us reuse the task parameters across nodes (ie: if we want a shared
 * start_date / end_date to be used in a number of calculations)
 */
export declare class RunSpec implements flatbuffers.IUnpackableObject<RunSpecT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): RunSpec;
    static getRootAsRunSpec(bb: flatbuffers.ByteBuffer, obj?: RunSpec): RunSpec;
    static getSizePrefixedRootAsRunSpec(bb: flatbuffers.ByteBuffer, obj?: RunSpec): RunSpec;
    persist(): boolean;
    schematic(obj?: ObjectId): ObjectId | null;
    paramIndices(index: number, obj?: ParamIndices): ParamIndices | null;
    paramIndicesLength(): number;
    params(index: number, obj?: TaskParameter): TaskParameter | null;
    paramsLength(): number;
    priority(): TaskPriority;
    notify(): boolean;
    attributes(index: number, obj?: Attr): Attr | null;
    attributesLength(): number;
    static startRunSpec(builder: flatbuffers.Builder): void;
    static addPersist(builder: flatbuffers.Builder, persist: boolean): void;
    static addSchematic(builder: flatbuffers.Builder, schematicOffset: flatbuffers.Offset): void;
    static addParamIndices(builder: flatbuffers.Builder, paramIndicesOffset: flatbuffers.Offset): void;
    static createParamIndicesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startParamIndicesVector(builder: flatbuffers.Builder, numElems: number): void;
    static addParams(builder: flatbuffers.Builder, paramsOffset: flatbuffers.Offset): void;
    static createParamsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startParamsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addPriority(builder: flatbuffers.Builder, priority: TaskPriority): void;
    static addNotify(builder: flatbuffers.Builder, notify: boolean): void;
    static addAttributes(builder: flatbuffers.Builder, attributesOffset: flatbuffers.Offset): void;
    static createAttributesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startAttributesVector(builder: flatbuffers.Builder, numElems: number): void;
    static endRunSpec(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): RunSpecT;
    unpackTo(_o: RunSpecT): void;
}
export declare class RunSpecT implements flatbuffers.IGeneratedObject {
    persist: boolean;
    schematic: ObjectIdT | null;
    paramIndices: (ParamIndicesT)[];
    params: (TaskParameterT)[];
    priority: TaskPriority;
    notify: boolean;
    attributes: (AttrT)[];
    constructor(persist?: boolean, schematic?: ObjectIdT | null, paramIndices?: (ParamIndicesT)[], params?: (TaskParameterT)[], priority?: TaskPriority, notify?: boolean, attributes?: (AttrT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=run-spec.d.ts.map