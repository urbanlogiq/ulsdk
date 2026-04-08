import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { HierarchicalRelationship, HierarchicalRelationshipT } from './hierarchical-relationship';
export declare class HierarchyRelationshipData implements flatbuffers.IUnpackableObject<HierarchyRelationshipDataT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): HierarchyRelationshipData;
    static getRootAsHierarchyRelationshipData(bb: flatbuffers.ByteBuffer, obj?: HierarchyRelationshipData): HierarchyRelationshipData;
    static getSizePrefixedRootAsHierarchyRelationshipData(bb: flatbuffers.ByteBuffer, obj?: HierarchyRelationshipData): HierarchyRelationshipData;
    hierarchy(index: number, obj?: HierarchicalRelationship): HierarchicalRelationship | null;
    hierarchyLength(): number;
    static startHierarchyRelationshipData(builder: flatbuffers.Builder): void;
    static addHierarchy(builder: flatbuffers.Builder, hierarchyOffset: flatbuffers.Offset): void;
    static createHierarchyVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startHierarchyVector(builder: flatbuffers.Builder, numElems: number): void;
    static endHierarchyRelationshipData(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createHierarchyRelationshipData(builder: flatbuffers.Builder, hierarchyOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): HierarchyRelationshipDataT;
    unpackTo(_o: HierarchyRelationshipDataT): void;
}
export declare class HierarchyRelationshipDataT implements flatbuffers.IGeneratedObject {
    hierarchy: (HierarchicalRelationshipT)[];
    constructor(hierarchy?: (HierarchicalRelationshipT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=hierarchy-relationship-data.d.ts.map