import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Attr, AttrT } from './attr';
import { ContentId, ContentIdT } from './content-id';
import { OpEntry, OpEntryT } from './op-entry';
/**
 * A DiffStream encodes a sequence of operations that should be performed on a table.
 * The operations are applied in order to the table, i.e. the ordering of the `seq` field is significant.
 */
export declare class DiffStream implements flatbuffers.IUnpackableObject<DiffStreamT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DiffStream;
    static getRootAsDiffStream(bb: flatbuffers.ByteBuffer, obj?: DiffStream): DiffStream;
    static getSizePrefixedRootAsDiffStream(bb: flatbuffers.ByteBuffer, obj?: DiffStream): DiffStream;
    /**
     * This is the head revision of the directory object that contains the table.
     */
    base(obj?: ContentId): ContentId | null;
    seq(index: number, obj?: OpEntry): OpEntry | null;
    seqLength(): number;
    /**
     * We can optionally associate attributes with the diffstream.
     * When the change history of the table is retrieved, the attributes from the diffstream
     * will be accessible as the `attributes` field on the ChangeSet associated with this diffstream.
     */
    attributes(index: number, obj?: Attr): Attr | null;
    attributesLength(): number;
    static startDiffStream(builder: flatbuffers.Builder): void;
    static addBase(builder: flatbuffers.Builder, baseOffset: flatbuffers.Offset): void;
    static addSeq(builder: flatbuffers.Builder, seqOffset: flatbuffers.Offset): void;
    static createSeqVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startSeqVector(builder: flatbuffers.Builder, numElems: number): void;
    static addAttributes(builder: flatbuffers.Builder, attributesOffset: flatbuffers.Offset): void;
    static createAttributesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startAttributesVector(builder: flatbuffers.Builder, numElems: number): void;
    static endDiffStream(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDiffStream(builder: flatbuffers.Builder, baseOffset: flatbuffers.Offset, seqOffset: flatbuffers.Offset, attributesOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DiffStreamT;
    unpackTo(_o: DiffStreamT): void;
}
export declare class DiffStreamT implements flatbuffers.IGeneratedObject {
    base: ContentIdT | null;
    seq: (OpEntryT)[];
    attributes: (AttrT)[];
    constructor(base?: ContentIdT | null, seq?: (OpEntryT)[], attributes?: (AttrT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=diff-stream.d.ts.map