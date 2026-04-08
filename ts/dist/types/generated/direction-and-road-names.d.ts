import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { DirectionAndRoadName, DirectionAndRoadNameT } from './direction-and-road-name';
export declare class DirectionAndRoadNames implements flatbuffers.IUnpackableObject<DirectionAndRoadNamesT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DirectionAndRoadNames;
    static getRootAsDirectionAndRoadNames(bb: flatbuffers.ByteBuffer, obj?: DirectionAndRoadNames): DirectionAndRoadNames;
    static getSizePrefixedRootAsDirectionAndRoadNames(bb: flatbuffers.ByteBuffer, obj?: DirectionAndRoadNames): DirectionAndRoadNames;
    directionAndRoadNames(index: number, obj?: DirectionAndRoadName): DirectionAndRoadName | null;
    directionAndRoadNamesLength(): number;
    static startDirectionAndRoadNames(builder: flatbuffers.Builder): void;
    static addDirectionAndRoadNames(builder: flatbuffers.Builder, directionAndRoadNamesOffset: flatbuffers.Offset): void;
    static createDirectionAndRoadNamesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startDirectionAndRoadNamesVector(builder: flatbuffers.Builder, numElems: number): void;
    static endDirectionAndRoadNames(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDirectionAndRoadNames(builder: flatbuffers.Builder, directionAndRoadNamesOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DirectionAndRoadNamesT;
    unpackTo(_o: DirectionAndRoadNamesT): void;
}
export declare class DirectionAndRoadNamesT implements flatbuffers.IGeneratedObject {
    directionAndRoadNames: (DirectionAndRoadNameT)[];
    constructor(directionAndRoadNames?: (DirectionAndRoadNameT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=direction-and-road-names.d.ts.map