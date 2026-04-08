import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * This variant indicates that if there is a conflict, the action is to "do
 * nothing", or to skip the conflicting rows.
 */
export declare class DoNothing implements flatbuffers.IUnpackableObject<DoNothingT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DoNothing;
    static getRootAsDoNothing(bb: flatbuffers.ByteBuffer, obj?: DoNothing): DoNothing;
    static getSizePrefixedRootAsDoNothing(bb: flatbuffers.ByteBuffer, obj?: DoNothing): DoNothing;
    static startDoNothing(builder: flatbuffers.Builder): void;
    static endDoNothing(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDoNothing(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): DoNothingT;
    unpackTo(_o: DoNothingT): void;
}
export declare class DoNothingT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=do-nothing.d.ts.map