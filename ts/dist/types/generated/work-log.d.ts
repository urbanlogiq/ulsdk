import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
import { UserSettings, UserSettingsT } from './user-settings';
import { WorklogParameter, WorklogParameterT } from './worklog-parameter';
export declare class WorkLog implements flatbuffers.IUnpackableObject<WorkLogT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): WorkLog;
    static getRootAsWorkLog(bb: flatbuffers.ByteBuffer, obj?: WorkLog): WorkLog;
    static getSizePrefixedRootAsWorkLog(bb: flatbuffers.ByteBuffer, obj?: WorkLog): WorkLog;
    /**
     * A human-readable tag.
     */
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    /**
     * Input streams and/or worklogs. These may be either work logs or streams.
     */
    inputStreams(index: number, obj?: ObjectId): ObjectId | null;
    inputStreamsLength(): number;
    /**
     * The schematic used behind creating the worklog. This may be empty/null
     * if we are just layering data, for example.
     */
    schematic(obj?: ObjectId): ObjectId | null;
    /**
     * The output_streams contain a list of Parquet documents that consist of
     * the results. These documents may expire (ie: if this is a temporary
     * step) so there should be enough information in the worklog necessary
     * to reconstruct these output streams.
     */
    outputStreams(index: number, obj?: ObjectId): ObjectId | null;
    outputStreamsLength(): number;
    /**
     * These are the serialized parameters passed into the task which created
     * this worklog.
     */
    params(index: number, obj?: WorklogParameter): WorklogParameter | null;
    paramsLength(): number;
    /**
     * Worklogs can contain multiple "levels". Consider the case where the user
     * submits a request for multiple ADT reports. We will create separate ADT
     * reports as required but also one that ties them all together. There are a
     * couple reasons for this; the primary is that the output of a schematic
     * node is allocated before the job is run and before it knows how many
     * worklogs will be generated. Another is that it makes it it easy (or
     * easier) to organize because we can sort based on "stuff the user requested",
     * instead of just "stuff the system generated".
     */
    parent(obj?: ObjectId): ObjectId | null;
    userSettings(obj?: UserSettings): UserSettings | null;
    jobId(obj?: ObjectId): ObjectId | null;
    static startWorkLog(builder: flatbuffers.Builder): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static addInputStreams(builder: flatbuffers.Builder, inputStreamsOffset: flatbuffers.Offset): void;
    static createInputStreamsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startInputStreamsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addSchematic(builder: flatbuffers.Builder, schematicOffset: flatbuffers.Offset): void;
    static addOutputStreams(builder: flatbuffers.Builder, outputStreamsOffset: flatbuffers.Offset): void;
    static createOutputStreamsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startOutputStreamsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addParams(builder: flatbuffers.Builder, paramsOffset: flatbuffers.Offset): void;
    static createParamsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startParamsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addParent(builder: flatbuffers.Builder, parentOffset: flatbuffers.Offset): void;
    static addUserSettings(builder: flatbuffers.Builder, userSettingsOffset: flatbuffers.Offset): void;
    static addJobId(builder: flatbuffers.Builder, jobIdOffset: flatbuffers.Offset): void;
    static endWorkLog(builder: flatbuffers.Builder): flatbuffers.Offset;
    static finishWorkLogBuffer(builder: flatbuffers.Builder, offset: flatbuffers.Offset): void;
    static finishSizePrefixedWorkLogBuffer(builder: flatbuffers.Builder, offset: flatbuffers.Offset): void;
    unpack(): WorkLogT;
    unpackTo(_o: WorkLogT): void;
}
export declare class WorkLogT implements flatbuffers.IGeneratedObject {
    name: string | Uint8Array | null;
    inputStreams: (ObjectIdT)[];
    schematic: ObjectIdT | null;
    outputStreams: (ObjectIdT)[];
    params: (WorklogParameterT)[];
    parent: ObjectIdT | null;
    userSettings: UserSettingsT | null;
    jobId: ObjectIdT | null;
    constructor(name?: string | Uint8Array | null, inputStreams?: (ObjectIdT)[], schematic?: ObjectIdT | null, outputStreams?: (ObjectIdT)[], params?: (WorklogParameterT)[], parent?: ObjectIdT | null, userSettings?: UserSettingsT | null, jobId?: ObjectIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=work-log.d.ts.map