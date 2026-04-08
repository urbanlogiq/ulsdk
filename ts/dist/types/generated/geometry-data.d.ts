import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { GeometryDataUnion } from './geometry-data-union';
import { NodeIdPairT } from './node-id-pair';
import { RawGeomT } from './raw-geom';
export declare class GeometryData implements flatbuffers.IUnpackableObject<GeometryDataT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): GeometryData;
    static getRootAsGeometryData(bb: flatbuffers.ByteBuffer, obj?: GeometryData): GeometryData;
    static getSizePrefixedRootAsGeometryData(bb: flatbuffers.ByteBuffer, obj?: GeometryData): GeometryData;
    dataType(): GeometryDataUnion;
    data<T extends flatbuffers.Table>(obj: any): any | null;
    static startGeometryData(builder: flatbuffers.Builder): void;
    static addDataType(builder: flatbuffers.Builder, dataType: GeometryDataUnion): void;
    static addData(builder: flatbuffers.Builder, dataOffset: flatbuffers.Offset): void;
    static endGeometryData(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createGeometryData(builder: flatbuffers.Builder, dataType: GeometryDataUnion, dataOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): GeometryDataT;
    unpackTo(_o: GeometryDataT): void;
}
export declare class GeometryDataT implements flatbuffers.IGeneratedObject {
    dataType: GeometryDataUnion;
    data: NodeIdPairT | RawGeomT | null;
    constructor(dataType?: GeometryDataUnion, data?: NodeIdPairT | RawGeomT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=geometry-data.d.ts.map