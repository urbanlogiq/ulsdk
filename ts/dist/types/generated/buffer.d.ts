import * as flatbuffers from 'flatbuffers/js/flatbuffers';
/**
 * ----------------------------------------------------------------------
 * A Buffer represents a single contiguous memory segment
 */
export declare class Buffer implements flatbuffers.IUnpackableObject<BufferT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Buffer;
    /**
     * The relative offset into the shared memory page where the bytes for this
     * buffer starts
     */
    offset(): bigint;
    /**
     * The absolute length (in bytes) of the memory buffer. The memory is found
     * from offset (inclusive) to offset + length (non-inclusive). When building
     * messages using the encapsulated IPC message, padding bytes may be written
     * after a buffer, but such padding bytes do not need to be accounted for in
     * the size here.
     */
    length(): bigint;
    static sizeOf(): number;
    static createBuffer(builder: flatbuffers.Builder, offset: bigint, length: bigint): flatbuffers.Offset;
    unpack(): BufferT;
    unpackTo(_o: BufferT): void;
}
export declare class BufferT implements flatbuffers.IGeneratedObject {
    offset: bigint;
    length: bigint;
    constructor(offset?: bigint, length?: bigint);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=buffer.d.ts.map