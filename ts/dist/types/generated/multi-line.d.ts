import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Line, LineT } from './line';
export declare class MultiLine implements flatbuffers.IUnpackableObject<MultiLineT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): MultiLine;
    static getRootAsMultiLine(bb: flatbuffers.ByteBuffer, obj?: MultiLine): MultiLine;
    static getSizePrefixedRootAsMultiLine(bb: flatbuffers.ByteBuffer, obj?: MultiLine): MultiLine;
    multilineGeo(index: number, obj?: Line): Line | null;
    multilineGeoLength(): number;
    static startMultiLine(builder: flatbuffers.Builder): void;
    static addMultilineGeo(builder: flatbuffers.Builder, multilineGeoOffset: flatbuffers.Offset): void;
    static createMultilineGeoVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startMultilineGeoVector(builder: flatbuffers.Builder, numElems: number): void;
    static endMultiLine(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createMultiLine(builder: flatbuffers.Builder, multilineGeoOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): MultiLineT;
    unpackTo(_o: MultiLineT): void;
}
export declare class MultiLineT implements flatbuffers.IGeneratedObject {
    multilineGeo: (LineT)[];
    constructor(multilineGeo?: (LineT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=multi-line.d.ts.map