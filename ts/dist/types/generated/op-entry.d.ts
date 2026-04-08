import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { AppendT } from './append';
import { Op } from './op';
import { RestoreRowT } from './restore-row';
import { RmRowT } from './rm-row';
import { SetT } from './set';
export declare class OpEntry implements flatbuffers.IUnpackableObject<OpEntryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): OpEntry;
    static getRootAsOpEntry(bb: flatbuffers.ByteBuffer, obj?: OpEntry): OpEntry;
    static getSizePrefixedRootAsOpEntry(bb: flatbuffers.ByteBuffer, obj?: OpEntry): OpEntry;
    opType(): Op;
    op<T extends flatbuffers.Table>(obj: any): any | null;
    static startOpEntry(builder: flatbuffers.Builder): void;
    static addOpType(builder: flatbuffers.Builder, opType: Op): void;
    static addOp(builder: flatbuffers.Builder, opOffset: flatbuffers.Offset): void;
    static endOpEntry(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createOpEntry(builder: flatbuffers.Builder, opType: Op, opOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): OpEntryT;
    unpackTo(_o: OpEntryT): void;
}
export declare class OpEntryT implements flatbuffers.IGeneratedObject {
    opType: Op;
    op: AppendT | RestoreRowT | RmRowT | SetT | null;
    constructor(opType?: Op, op?: AppendT | RestoreRowT | RmRowT | SetT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=op-entry.d.ts.map