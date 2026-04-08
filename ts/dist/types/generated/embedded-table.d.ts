import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class EmbeddedTable implements flatbuffers.IUnpackableObject<EmbeddedTableT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): EmbeddedTable;
    static getRootAsEmbeddedTable(bb: flatbuffers.ByteBuffer, obj?: EmbeddedTable): EmbeddedTable;
    static getSizePrefixedRootAsEmbeddedTable(bb: flatbuffers.ByteBuffer, obj?: EmbeddedTable): EmbeddedTable;
    v(index: number): number | null;
    vLength(): number;
    vArray(): Uint8Array | null;
    static startEmbeddedTable(builder: flatbuffers.Builder): void;
    static addV(builder: flatbuffers.Builder, vOffset: flatbuffers.Offset): void;
    static createVVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startVVector(builder: flatbuffers.Builder, numElems: number): void;
    static endEmbeddedTable(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createEmbeddedTable(builder: flatbuffers.Builder, vOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): EmbeddedTableT;
    unpackTo(_o: EmbeddedTableT): void;
}
export declare class EmbeddedTableT implements flatbuffers.IGeneratedObject {
    v: (number)[];
    constructor(v?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=embedded-table.d.ts.map