import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { NestedCategoryRelationshipNode, NestedCategoryRelationshipNodeT } from './nested-category-relationship-node';
export declare class NestedCategoryRelationshipData implements flatbuffers.IUnpackableObject<NestedCategoryRelationshipDataT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NestedCategoryRelationshipData;
    static getRootAsNestedCategoryRelationshipData(bb: flatbuffers.ByteBuffer, obj?: NestedCategoryRelationshipData): NestedCategoryRelationshipData;
    static getSizePrefixedRootAsNestedCategoryRelationshipData(bb: flatbuffers.ByteBuffer, obj?: NestedCategoryRelationshipData): NestedCategoryRelationshipData;
    categories(index: number, obj?: NestedCategoryRelationshipNode): NestedCategoryRelationshipNode | null;
    categoriesLength(): number;
    static startNestedCategoryRelationshipData(builder: flatbuffers.Builder): void;
    static addCategories(builder: flatbuffers.Builder, categoriesOffset: flatbuffers.Offset): void;
    static createCategoriesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startCategoriesVector(builder: flatbuffers.Builder, numElems: number): void;
    static endNestedCategoryRelationshipData(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createNestedCategoryRelationshipData(builder: flatbuffers.Builder, categoriesOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): NestedCategoryRelationshipDataT;
    unpackTo(_o: NestedCategoryRelationshipDataT): void;
}
export declare class NestedCategoryRelationshipDataT implements flatbuffers.IGeneratedObject {
    categories: (NestedCategoryRelationshipNodeT)[];
    constructor(categories?: (NestedCategoryRelationshipNodeT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=nested-category-relationship-data.d.ts.map