import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class DatacatalogGeometry implements flatbuffers.IUnpackableObject<DatacatalogGeometryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DatacatalogGeometry;
    static getRootAsDatacatalogGeometry(bb: flatbuffers.ByteBuffer, obj?: DatacatalogGeometry): DatacatalogGeometry;
    static getSizePrefixedRootAsDatacatalogGeometry(bb: flatbuffers.ByteBuffer, obj?: DatacatalogGeometry): DatacatalogGeometry;
    column(): string | null;
    column(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startDatacatalogGeometry(builder: flatbuffers.Builder): void;
    static addColumn(builder: flatbuffers.Builder, columnOffset: flatbuffers.Offset): void;
    static endDatacatalogGeometry(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDatacatalogGeometry(builder: flatbuffers.Builder, columnOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DatacatalogGeometryT;
    unpackTo(_o: DatacatalogGeometryT): void;
}
export declare class DatacatalogGeometryT implements flatbuffers.IGeneratedObject {
    column: string | Uint8Array | null;
    constructor(column?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=datacatalog-geometry.d.ts.map