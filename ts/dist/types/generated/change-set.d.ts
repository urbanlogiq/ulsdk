import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Attr, AttrT } from './attr';
import { B2cId, B2cIdT } from './b2c-id';
import { ChangeOpEntry, ChangeOpEntryT } from './change-op-entry';
import { ContentId, ContentIdT } from './content-id';
export declare class ChangeSet implements flatbuffers.IUnpackableObject<ChangeSetT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ChangeSet;
    static getRootAsChangeSet(bb: flatbuffers.ByteBuffer, obj?: ChangeSet): ChangeSet;
    static getSizePrefixedRootAsChangeSet(bb: flatbuffers.ByteBuffer, obj?: ChangeSet): ChangeSet;
    revision(obj?: ContentId): ContentId | null;
    who(obj?: B2cId): B2cId | null;
    when(): bigint;
    ops(index: number, obj?: ChangeOpEntry): ChangeOpEntry | null;
    opsLength(): number;
    attributes(index: number, obj?: Attr): Attr | null;
    attributesLength(): number;
    static startChangeSet(builder: flatbuffers.Builder): void;
    static addRevision(builder: flatbuffers.Builder, revisionOffset: flatbuffers.Offset): void;
    static addWho(builder: flatbuffers.Builder, whoOffset: flatbuffers.Offset): void;
    static addWhen(builder: flatbuffers.Builder, when: bigint): void;
    static addOps(builder: flatbuffers.Builder, opsOffset: flatbuffers.Offset): void;
    static createOpsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startOpsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addAttributes(builder: flatbuffers.Builder, attributesOffset: flatbuffers.Offset): void;
    static createAttributesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startAttributesVector(builder: flatbuffers.Builder, numElems: number): void;
    static endChangeSet(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): ChangeSetT;
    unpackTo(_o: ChangeSetT): void;
}
export declare class ChangeSetT implements flatbuffers.IGeneratedObject {
    revision: ContentIdT | null;
    who: B2cIdT | null;
    when: bigint;
    ops: (ChangeOpEntryT)[];
    attributes: (AttrT)[];
    constructor(revision?: ContentIdT | null, who?: B2cIdT | null, when?: bigint, ops?: (ChangeOpEntryT)[], attributes?: (AttrT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=change-set.d.ts.map