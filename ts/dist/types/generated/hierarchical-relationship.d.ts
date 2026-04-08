import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class HierarchicalRelationship implements flatbuffers.IUnpackableObject<HierarchicalRelationshipT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): HierarchicalRelationship;
    static getRootAsHierarchicalRelationship(bb: flatbuffers.ByteBuffer, obj?: HierarchicalRelationship): HierarchicalRelationship;
    static getSizePrefixedRootAsHierarchicalRelationship(bb: flatbuffers.ByteBuffer, obj?: HierarchicalRelationship): HierarchicalRelationship;
    parent(): number;
    children(index: number): number | null;
    childrenLength(): number;
    childrenArray(): Int32Array | null;
    static startHierarchicalRelationship(builder: flatbuffers.Builder): void;
    static addParent(builder: flatbuffers.Builder, parent: number): void;
    static addChildren(builder: flatbuffers.Builder, childrenOffset: flatbuffers.Offset): void;
    static createChildrenVector(builder: flatbuffers.Builder, data: number[] | Int32Array): flatbuffers.Offset;
    /**
     * @deprecated This Uint8Array overload will be removed in the future.
     */
    static createChildrenVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startChildrenVector(builder: flatbuffers.Builder, numElems: number): void;
    static endHierarchicalRelationship(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createHierarchicalRelationship(builder: flatbuffers.Builder, parent: number, childrenOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): HierarchicalRelationshipT;
    unpackTo(_o: HierarchicalRelationshipT): void;
}
export declare class HierarchicalRelationshipT implements flatbuffers.IGeneratedObject {
    parent: number;
    children: (number)[];
    constructor(parent?: number, children?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=hierarchical-relationship.d.ts.map