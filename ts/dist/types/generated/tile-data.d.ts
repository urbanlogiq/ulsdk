import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { Layout, LayoutT } from './layout';
import { TileSettings, TileSettingsT } from './tile-settings';
export declare class TileData implements flatbuffers.IUnpackableObject<TileDataT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): TileData;
    static getRootAsTileData(bb: flatbuffers.ByteBuffer, obj?: TileData): TileData;
    static getSizePrefixedRootAsTileData(bb: flatbuffers.ByteBuffer, obj?: TileData): TileData;
    layout(obj?: Layout): Layout | null;
    tileSettings(obj?: TileSettings): TileSettings | null;
    static startTileData(builder: flatbuffers.Builder): void;
    static addLayout(builder: flatbuffers.Builder, layoutOffset: flatbuffers.Offset): void;
    static addTileSettings(builder: flatbuffers.Builder, tileSettingsOffset: flatbuffers.Offset): void;
    static endTileData(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): TileDataT;
    unpackTo(_o: TileDataT): void;
}
export declare class TileDataT implements flatbuffers.IGeneratedObject {
    layout: LayoutT | null;
    tileSettings: TileSettingsT | null;
    constructor(layout?: LayoutT | null, tileSettings?: TileSettingsT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=tile-data.d.ts.map