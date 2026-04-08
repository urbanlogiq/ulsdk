import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { NestedHierarchyRelationshipNode, NestedHierarchyRelationshipNodeT } from './nested-hierarchy-relationship-node';
export declare class NestedHierarchyRelationshipData implements flatbuffers.IUnpackableObject<NestedHierarchyRelationshipDataT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NestedHierarchyRelationshipData;
    static getRootAsNestedHierarchyRelationshipData(bb: flatbuffers.ByteBuffer, obj?: NestedHierarchyRelationshipData): NestedHierarchyRelationshipData;
    static getSizePrefixedRootAsNestedHierarchyRelationshipData(bb: flatbuffers.ByteBuffer, obj?: NestedHierarchyRelationshipData): NestedHierarchyRelationshipData;
    nodes(index: number, obj?: NestedHierarchyRelationshipNode): NestedHierarchyRelationshipNode | null;
    nodesLength(): number;
    static startNestedHierarchyRelationshipData(builder: flatbuffers.Builder): void;
    static addNodes(builder: flatbuffers.Builder, nodesOffset: flatbuffers.Offset): void;
    static createNodesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startNodesVector(builder: flatbuffers.Builder, numElems: number): void;
    static endNestedHierarchyRelationshipData(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createNestedHierarchyRelationshipData(builder: flatbuffers.Builder, nodesOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): NestedHierarchyRelationshipDataT;
    unpackTo(_o: NestedHierarchyRelationshipDataT): void;
}
export declare class NestedHierarchyRelationshipDataT implements flatbuffers.IGeneratedObject {
    nodes: (NestedHierarchyRelationshipNodeT)[];
    constructor(nodes?: (NestedHierarchyRelationshipNodeT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=nested-hierarchy-relationship-data.d.ts.map