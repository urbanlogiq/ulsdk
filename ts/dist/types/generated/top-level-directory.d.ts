import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { B2cId, B2cIdT } from './b2c-id';
export declare class TopLevelDirectory implements flatbuffers.IUnpackableObject<TopLevelDirectoryT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): TopLevelDirectory;
    static getRootAsTopLevelDirectory(bb: flatbuffers.ByteBuffer, obj?: TopLevelDirectory): TopLevelDirectory;
    static getSizePrefixedRootAsTopLevelDirectory(bb: flatbuffers.ByteBuffer, obj?: TopLevelDirectory): TopLevelDirectory;
    b2cEntity(obj?: B2cId): B2cId | null;
    static startTopLevelDirectory(builder: flatbuffers.Builder): void;
    static addB2cEntity(builder: flatbuffers.Builder, b2cEntityOffset: flatbuffers.Offset): void;
    static endTopLevelDirectory(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createTopLevelDirectory(builder: flatbuffers.Builder, b2cEntityOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): TopLevelDirectoryT;
    unpackTo(_o: TopLevelDirectoryT): void;
}
export declare class TopLevelDirectoryT implements flatbuffers.IGeneratedObject {
    b2cEntity: B2cIdT | null;
    constructor(b2cEntity?: B2cIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=top-level-directory.d.ts.map