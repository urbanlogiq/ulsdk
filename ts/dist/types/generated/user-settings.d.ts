import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { TileData, TileDataT } from './tile-data';
export declare class UserSettings implements flatbuffers.IUnpackableObject<UserSettingsT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): UserSettings;
    static getRootAsUserSettings(bb: flatbuffers.ByteBuffer, obj?: UserSettings): UserSettings;
    static getSizePrefixedRootAsUserSettings(bb: flatbuffers.ByteBuffer, obj?: UserSettings): UserSettings;
    tileData(index: number, obj?: TileData): TileData | null;
    tileDataLength(): number;
    isTemplate(): boolean;
    static startUserSettings(builder: flatbuffers.Builder): void;
    static addTileData(builder: flatbuffers.Builder, tileDataOffset: flatbuffers.Offset): void;
    static createTileDataVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startTileDataVector(builder: flatbuffers.Builder, numElems: number): void;
    static addIsTemplate(builder: flatbuffers.Builder, isTemplate: boolean): void;
    static endUserSettings(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createUserSettings(builder: flatbuffers.Builder, tileDataOffset: flatbuffers.Offset, isTemplate: boolean): flatbuffers.Offset;
    unpack(): UserSettingsT;
    unpackTo(_o: UserSettingsT): void;
}
export declare class UserSettingsT implements flatbuffers.IGeneratedObject {
    tileData: (TileDataT)[];
    isTemplate: boolean;
    constructor(tileData?: (TileDataT)[], isTemplate?: boolean);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=user-settings.d.ts.map