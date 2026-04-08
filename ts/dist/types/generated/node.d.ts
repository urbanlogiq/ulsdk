import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ObjectId, ObjectIdT } from './object-id';
export declare class Node implements flatbuffers.IUnpackableObject<NodeT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Node;
    static getRootAsNode(bb: flatbuffers.ByteBuffer, obj?: Node): Node;
    static getSizePrefixedRootAsNode(bb: flatbuffers.ByteBuffer, obj?: Node): Node;
    obj(obj?: ObjectId): ObjectId | null;
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startNode(builder: flatbuffers.Builder): void;
    static addObj(builder: flatbuffers.Builder, objOffset: flatbuffers.Offset): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static endNode(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createNode(builder: flatbuffers.Builder, objOffset: flatbuffers.Offset, nameOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): NodeT;
    unpackTo(_o: NodeT): void;
}
export declare class NodeT implements flatbuffers.IGeneratedObject {
    obj: ObjectIdT | null;
    name: string | Uint8Array | null;
    constructor(obj?: ObjectIdT | null, name?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=node.d.ts.map