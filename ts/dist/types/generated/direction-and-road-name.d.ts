import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class DirectionAndRoadName implements flatbuffers.IUnpackableObject<DirectionAndRoadNameT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DirectionAndRoadName;
    static getRootAsDirectionAndRoadName(bb: flatbuffers.ByteBuffer, obj?: DirectionAndRoadName): DirectionAndRoadName;
    static getSizePrefixedRootAsDirectionAndRoadName(bb: flatbuffers.ByteBuffer, obj?: DirectionAndRoadName): DirectionAndRoadName;
    direction(): string | null;
    direction(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    roadName(): string | null;
    roadName(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startDirectionAndRoadName(builder: flatbuffers.Builder): void;
    static addDirection(builder: flatbuffers.Builder, directionOffset: flatbuffers.Offset): void;
    static addRoadName(builder: flatbuffers.Builder, roadNameOffset: flatbuffers.Offset): void;
    static endDirectionAndRoadName(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDirectionAndRoadName(builder: flatbuffers.Builder, directionOffset: flatbuffers.Offset, roadNameOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DirectionAndRoadNameT;
    unpackTo(_o: DirectionAndRoadNameT): void;
}
export declare class DirectionAndRoadNameT implements flatbuffers.IGeneratedObject {
    direction: string | Uint8Array | null;
    roadName: string | Uint8Array | null;
    constructor(direction?: string | Uint8Array | null, roadName?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=direction-and-road-name.d.ts.map