import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class NoGeometry implements flatbuffers.IUnpackableObject<NoGeometryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NoGeometry;
    static getRootAsNoGeometry(bb: flatbuffers.ByteBuffer, obj?: NoGeometry): NoGeometry;
    static getSizePrefixedRootAsNoGeometry(bb: flatbuffers.ByteBuffer, obj?: NoGeometry): NoGeometry;
    static startNoGeometry(builder: flatbuffers.Builder): void;
    static endNoGeometry(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createNoGeometry(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): NoGeometryT;
    unpackTo(_o: NoGeometryT): void;
}
export declare class NoGeometryT implements flatbuffers.IGeneratedObject {
    constructor();
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=no-geometry.d.ts.map