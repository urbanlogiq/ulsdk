import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class DataStateId implements flatbuffers.IUnpackableObject<DataStateIdT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DataStateId;
    static getRootAsDataStateId(bb: flatbuffers.ByteBuffer, obj?: DataStateId): DataStateId;
    static getSizePrefixedRootAsDataStateId(bb: flatbuffers.ByteBuffer, obj?: DataStateId): DataStateId;
    b(index: number): number | null;
    bLength(): number;
    bArray(): Uint8Array | null;
    static startDataStateId(builder: flatbuffers.Builder): void;
    static addB(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): void;
    static createBVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startBVector(builder: flatbuffers.Builder, numElems: number): void;
    static endDataStateId(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDataStateId(builder: flatbuffers.Builder, bOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DataStateIdT;
    unpackTo(_o: DataStateIdT): void;
}
export declare class DataStateIdT implements flatbuffers.IGeneratedObject {
    b: (number)[];
    constructor(b?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=data-state-id.d.ts.map