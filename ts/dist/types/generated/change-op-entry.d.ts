import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ChangeOp } from './change-op';
import { DeleteT } from './delete';
import { ModifyT } from './modify';
import { RestoreT } from './restore';
export declare class ChangeOpEntry implements flatbuffers.IUnpackableObject<ChangeOpEntryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ChangeOpEntry;
    static getRootAsChangeOpEntry(bb: flatbuffers.ByteBuffer, obj?: ChangeOpEntry): ChangeOpEntry;
    static getSizePrefixedRootAsChangeOpEntry(bb: flatbuffers.ByteBuffer, obj?: ChangeOpEntry): ChangeOpEntry;
    opType(): ChangeOp;
    op<T extends flatbuffers.Table>(obj: any): any | null;
    static startChangeOpEntry(builder: flatbuffers.Builder): void;
    static addOpType(builder: flatbuffers.Builder, opType: ChangeOp): void;
    static addOp(builder: flatbuffers.Builder, opOffset: flatbuffers.Offset): void;
    static endChangeOpEntry(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createChangeOpEntry(builder: flatbuffers.Builder, opType: ChangeOp, opOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ChangeOpEntryT;
    unpackTo(_o: ChangeOpEntryT): void;
}
export declare class ChangeOpEntryT implements flatbuffers.IGeneratedObject {
    opType: ChangeOp;
    op: DeleteT | ModifyT | RestoreT | null;
    constructor(opType?: ChangeOp, op?: DeleteT | ModifyT | RestoreT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=change-op-entry.d.ts.map