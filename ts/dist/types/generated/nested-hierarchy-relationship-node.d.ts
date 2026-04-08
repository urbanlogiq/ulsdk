import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class NestedHierarchyRelationshipNode implements flatbuffers.IUnpackableObject<NestedHierarchyRelationshipNodeT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NestedHierarchyRelationshipNode;
    static getRootAsNestedHierarchyRelationshipNode(bb: flatbuffers.ByteBuffer, obj?: NestedHierarchyRelationshipNode): NestedHierarchyRelationshipNode;
    static getSizePrefixedRootAsNestedHierarchyRelationshipNode(bb: flatbuffers.ByteBuffer, obj?: NestedHierarchyRelationshipNode): NestedHierarchyRelationshipNode;
    label(): string | null;
    label(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    childNodes(index: number): number | null;
    childNodesLength(): number;
    childNodesArray(): Int32Array | null;
    childColumns(index: number): number | null;
    childColumnsLength(): number;
    childColumnsArray(): Int32Array | null;
    static startNestedHierarchyRelationshipNode(builder: flatbuffers.Builder): void;
    static addLabel(builder: flatbuffers.Builder, labelOffset: flatbuffers.Offset): void;
    static addChildNodes(builder: flatbuffers.Builder, childNodesOffset: flatbuffers.Offset): void;
    static createChildNodesVector(builder: flatbuffers.Builder, data: number[] | Int32Array): flatbuffers.Offset;
    /**
     * @deprecated This Uint8Array overload will be removed in the future.
     */
    static createChildNodesVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startChildNodesVector(builder: flatbuffers.Builder, numElems: number): void;
    static addChildColumns(builder: flatbuffers.Builder, childColumnsOffset: flatbuffers.Offset): void;
    static createChildColumnsVector(builder: flatbuffers.Builder, data: number[] | Int32Array): flatbuffers.Offset;
    /**
     * @deprecated This Uint8Array overload will be removed in the future.
     */
    static createChildColumnsVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startChildColumnsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endNestedHierarchyRelationshipNode(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createNestedHierarchyRelationshipNode(builder: flatbuffers.Builder, labelOffset: flatbuffers.Offset, childNodesOffset: flatbuffers.Offset, childColumnsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): NestedHierarchyRelationshipNodeT;
    unpackTo(_o: NestedHierarchyRelationshipNodeT): void;
}
export declare class NestedHierarchyRelationshipNodeT implements flatbuffers.IGeneratedObject {
    label: string | Uint8Array | null;
    childNodes: (number)[];
    childColumns: (number)[];
    constructor(label?: string | Uint8Array | null, childNodes?: (number)[], childColumns?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=nested-hierarchy-relationship-node.d.ts.map