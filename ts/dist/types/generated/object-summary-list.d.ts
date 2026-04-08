import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectSummary, ObjectSummaryT } from './object-summary';
export declare class ObjectSummaryList implements flatbuffers.IUnpackableObject<ObjectSummaryListT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ObjectSummaryList;
    static getRootAsObjectSummaryList(bb: flatbuffers.ByteBuffer, obj?: ObjectSummaryList): ObjectSummaryList;
    static getSizePrefixedRootAsObjectSummaryList(bb: flatbuffers.ByteBuffer, obj?: ObjectSummaryList): ObjectSummaryList;
    pairs(index: number, obj?: ObjectSummary): ObjectSummary | null;
    pairsLength(): number;
    static startObjectSummaryList(builder: flatbuffers.Builder): void;
    static addPairs(builder: flatbuffers.Builder, pairsOffset: flatbuffers.Offset): void;
    static createPairsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startPairsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endObjectSummaryList(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createObjectSummaryList(builder: flatbuffers.Builder, pairsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ObjectSummaryListT;
    unpackTo(_o: ObjectSummaryListT): void;
}
export declare class ObjectSummaryListT implements flatbuffers.IGeneratedObject {
    pairs: (ObjectSummaryT)[];
    constructor(pairs?: (ObjectSummaryT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=object-summary-list.d.ts.map