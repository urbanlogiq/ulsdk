import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class ParameterFlags implements flatbuffers.IUnpackableObject<ParameterFlagsT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ParameterFlags;
    static getRootAsParameterFlags(bb: flatbuffers.ByteBuffer, obj?: ParameterFlags): ParameterFlags;
    static getSizePrefixedRootAsParameterFlags(bb: flatbuffers.ByteBuffer, obj?: ParameterFlags): ParameterFlags;
    flags(): bigint;
    static startParameterFlags(builder: flatbuffers.Builder): void;
    static addFlags(builder: flatbuffers.Builder, flags: bigint): void;
    static endParameterFlags(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createParameterFlags(builder: flatbuffers.Builder, flags: bigint): flatbuffers.Offset;
    unpack(): ParameterFlagsT;
    unpackTo(_o: ParameterFlagsT): void;
}
export declare class ParameterFlagsT implements flatbuffers.IGeneratedObject {
    flags: bigint;
    constructor(flags?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=parameter-flags.d.ts.map