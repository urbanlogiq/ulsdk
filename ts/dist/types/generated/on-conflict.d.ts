import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ConflictAction } from './conflict-action';
import { DoNothingT } from './do-nothing';
import { DoUpdateT } from './do-update';
import { InsertConflictingT } from './insert-conflicting';
export declare class OnConflict implements flatbuffers.IUnpackableObject<OnConflictT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): OnConflict;
    static getRootAsOnConflict(bb: flatbuffers.ByteBuffer, obj?: OnConflict): OnConflict;
    static getSizePrefixedRootAsOnConflict(bb: flatbuffers.ByteBuffer, obj?: OnConflict): OnConflict;
    conflictTarget(index: number): string;
    conflictTarget(index: number, optionalEncoding: flatbuffers.Encoding): string | Uint8Array;
    conflictTargetLength(): number;
    actionType(): ConflictAction;
    action<T extends flatbuffers.Table>(obj: any): any | null;
    static startOnConflict(builder: flatbuffers.Builder): void;
    static addConflictTarget(builder: flatbuffers.Builder, conflictTargetOffset: flatbuffers.Offset): void;
    static createConflictTargetVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startConflictTargetVector(builder: flatbuffers.Builder, numElems: number): void;
    static addActionType(builder: flatbuffers.Builder, actionType: ConflictAction): void;
    static addAction(builder: flatbuffers.Builder, actionOffset: flatbuffers.Offset): void;
    static endOnConflict(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createOnConflict(builder: flatbuffers.Builder, conflictTargetOffset: flatbuffers.Offset, actionType: ConflictAction, actionOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): OnConflictT;
    unpackTo(_o: OnConflictT): void;
}
export declare class OnConflictT implements flatbuffers.IGeneratedObject {
    conflictTarget: (string)[];
    actionType: ConflictAction;
    action: DoNothingT | DoUpdateT | InsertConflictingT | null;
    constructor(conflictTarget?: (string)[], actionType?: ConflictAction, action?: DoNothingT | DoUpdateT | InsertConflictingT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=on-conflict.d.ts.map