import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class ColumnGroupId implements flatbuffers.IUnpackableObject<ColumnGroupIdT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ColumnGroupId;
    static getRootAsColumnGroupId(bb: flatbuffers.ByteBuffer, obj?: ColumnGroupId): ColumnGroupId;
    static getSizePrefixedRootAsColumnGroupId(bb: flatbuffers.ByteBuffer, obj?: ColumnGroupId): ColumnGroupId;
    b(index: number): number | null;
    bLength(): number;
    bArray(): Uint8Array | null;
    static startColumnGroupId(builder: flatbuffers.Builder): void;
    static addB(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): void;
    static createBVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startBVector(builder: flatbuffers.Builder, numElems: number): void;
    static endColumnGroupId(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createColumnGroupId(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ColumnGroupIdT;
    unpackTo(_o: ColumnGroupIdT): void;
}
export declare class ColumnGroupIdT implements flatbuffers.IGeneratedObject {
    b: (number)[];
    constructor(b?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=column-group-id.d.ts.map