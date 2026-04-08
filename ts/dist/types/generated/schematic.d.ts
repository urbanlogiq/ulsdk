import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { AttributePair, AttributePairT } from './attribute-pair';
import { Edge, EdgeT } from './edge';
import { Node, NodeT } from './node';
export declare class Schematic implements flatbuffers.IUnpackableObject<SchematicT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Schematic;
    static getRootAsSchematic(bb: flatbuffers.ByteBuffer, obj?: Schematic): Schematic;
    static getSizePrefixedRootAsSchematic(bb: flatbuffers.ByteBuffer, obj?: Schematic): Schematic;
    nodes(index: number, obj?: Node): Node | null;
    nodesLength(): number;
    edges(index: number, obj?: Edge): Edge | null;
    edgesLength(): number;
    attributes(index: number, obj?: AttributePair): AttributePair | null;
    attributesLength(): number;
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startSchematic(builder: flatbuffers.Builder): void;
    static addNodes(builder: flatbuffers.Builder, nodesOffset: flatbuffers.Offset): void;
    static createNodesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startNodesVector(builder: flatbuffers.Builder, numElems: number): void;
    static addEdges(builder: flatbuffers.Builder, edgesOffset: flatbuffers.Offset): void;
    static createEdgesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startEdgesVector(builder: flatbuffers.Builder, numElems: number): void;
    static addAttributes(builder: flatbuffers.Builder, attributesOffset: flatbuffers.Offset): void;
    static createAttributesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startAttributesVector(builder: flatbuffers.Builder, numElems: number): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static endSchematic(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createSchematic(builder: flatbuffers.Builder, nodesOffset: flatbuffers.Offset, edgesOffset: flatbuffers.Offset, attributesOffset: flatbuffers.Offset, nameOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): SchematicT;
    unpackTo(_o: SchematicT): void;
}
export declare class SchematicT implements flatbuffers.IGeneratedObject {
    nodes: (NodeT)[];
    edges: (EdgeT)[];
    attributes: (AttributePairT)[];
    name: string | Uint8Array | null;
    constructor(nodes?: (NodeT)[], edges?: (EdgeT)[], attributes?: (AttributePairT)[], name?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=schematic.d.ts.map