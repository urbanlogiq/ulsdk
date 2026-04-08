import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class NestedCategoryRelationshipNode implements flatbuffers.IUnpackableObject<NestedCategoryRelationshipNodeT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NestedCategoryRelationshipNode;
    static getRootAsNestedCategoryRelationshipNode(bb: flatbuffers.ByteBuffer, obj?: NestedCategoryRelationshipNode): NestedCategoryRelationshipNode;
    static getSizePrefixedRootAsNestedCategoryRelationshipNode(bb: flatbuffers.ByteBuffer, obj?: NestedCategoryRelationshipNode): NestedCategoryRelationshipNode;
    column(): number;
    childColumns(index: number): number | null;
    childColumnsLength(): number;
    childColumnsArray(): Int32Array | null;
    static startNestedCategoryRelationshipNode(builder: flatbuffers.Builder): void;
    static addColumn(builder: flatbuffers.Builder, column: number): void;
    static addChildColumns(builder: flatbuffers.Builder, childColumnsOffset: flatbuffers.Offset): void;
    static createChildColumnsVector(builder: flatbuffers.Builder, data: number[] | Int32Array): flatbuffers.Offset;
    /**
     * @deprecated This Uint8Array overload will be removed in the future.
     */
    static createChildColumnsVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startChildColumnsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endNestedCategoryRelationshipNode(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createNestedCategoryRelationshipNode(builder: flatbuffers.Builder, column: number, childColumnsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): NestedCategoryRelationshipNodeT;
    unpackTo(_o: NestedCategoryRelationshipNodeT): void;
}
export declare class NestedCategoryRelationshipNodeT implements flatbuffers.IGeneratedObject {
    column: number;
    childColumns: (number)[];
    constructor(column?: number, childColumns?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=nested-category-relationship-node.d.ts.map