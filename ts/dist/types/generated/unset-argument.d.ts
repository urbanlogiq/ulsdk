import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class UnsetArgument implements flatbuffers.IUnpackableObject<UnsetArgumentT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): UnsetArgument;
    static getRootAsUnsetArgument(bb: flatbuffers.ByteBuffer, obj?: UnsetArgument): UnsetArgument;
    static getSizePrefixedRootAsUnsetArgument(bb: flatbuffers.ByteBuffer, obj?: UnsetArgument): UnsetArgument;
    static startUnsetArgument(builder: flatbuffers.Builder): void;
    static endUnsetArgument(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createUnsetArgument(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): UnsetArgumentT;
    unpackTo(_o: UnsetArgumentT): void;
}
export declare class UnsetArgumentT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=unset-argument.d.ts.map