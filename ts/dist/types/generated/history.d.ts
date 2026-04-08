import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ChangeSet, ChangeSetT } from './change-set';
import { ContentId, ContentIdT } from './content-id';
export declare class History implements flatbuffers.IUnpackableObject<HistoryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): History;
    static getRootAsHistory(bb: flatbuffers.ByteBuffer, obj?: History): History;
    static getSizePrefixedRootAsHistory(bb: flatbuffers.ByteBuffer, obj?: History): History;
    changes(index: number, obj?: ChangeSet): ChangeSet | null;
    changesLength(): number;
    continuationId(obj?: ContentId): ContentId | null;
    static startHistory(builder: flatbuffers.Builder): void;
    static addChanges(builder: flatbuffers.Builder, changesOffset: flatbuffers.Offset): void;
    static createChangesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startChangesVector(builder: flatbuffers.Builder, numElems: number): void;
    static addContinuationId(builder: flatbuffers.Builder, continuationIdOffset: flatbuffers.Offset): void;
    static endHistory(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): HistoryT;
    unpackTo(_o: HistoryT): void;
}
export declare class HistoryT implements flatbuffers.IGeneratedObject {
    changes: (ChangeSetT)[];
    continuationId: ContentIdT | null;
    constructor(changes?: (ChangeSetT)[], continuationId?: ContentIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=history.d.ts.map