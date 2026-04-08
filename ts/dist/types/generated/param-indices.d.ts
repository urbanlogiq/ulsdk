import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class ParamIndices implements flatbuffers.IUnpackableObject<ParamIndicesT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ParamIndices;
    static getRootAsParamIndices(bb: flatbuffers.ByteBuffer, obj?: ParamIndices): ParamIndices;
    static getSizePrefixedRootAsParamIndices(bb: flatbuffers.ByteBuffer, obj?: ParamIndices): ParamIndices;
    idxs(index: number): number | null;
    idxsLength(): number;
    idxsArray(): Int32Array | null;
    static startParamIndices(builder: flatbuffers.Builder): void;
    static addIdxs(builder: flatbuffers.Builder, idxsOffset: flatbuffers.Offset): void;
    static createIdxsVector(builder: flatbuffers.Builder, data: number[] | Int32Array): flatbuffers.Offset;
    /**
     * @deprecated This Uint8Array overload will be removed in the future.
     */
    static createIdxsVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startIdxsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endParamIndices(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createParamIndices(builder: flatbuffers.Builder, idxsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ParamIndicesT;
    unpackTo(_o: ParamIndicesT): void;
}
export declare class ParamIndicesT implements flatbuffers.IGeneratedObject {
    idxs: (number)[];
    constructor(idxs?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=param-indices.d.ts.map