import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class CategoryRelationshipData implements flatbuffers.IUnpackableObject<CategoryRelationshipDataT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): CategoryRelationshipData;
    static getRootAsCategoryRelationshipData(bb: flatbuffers.ByteBuffer, obj?: CategoryRelationshipData): CategoryRelationshipData;
    static getSizePrefixedRootAsCategoryRelationshipData(bb: flatbuffers.ByteBuffer, obj?: CategoryRelationshipData): CategoryRelationshipData;
    categories(index: number): number | null;
    categoriesLength(): number;
    categoriesArray(): Int32Array | null;
    associatedFields(index: number): number | null;
    associatedFieldsLength(): number;
    associatedFieldsArray(): Int32Array | null;
    static startCategoryRelationshipData(builder: flatbuffers.Builder): void;
    static addCategories(builder: flatbuffers.Builder, categoriesOffset: flatbuffers.Offset): void;
    static createCategoriesVector(builder: flatbuffers.Builder, data: number[] | Int32Array): flatbuffers.Offset;
    /**
     * @deprecated This Uint8Array overload will be removed in the future.
     */
    static createCategoriesVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startCategoriesVector(builder: flatbuffers.Builder, numElems: number): void;
    static addAssociatedFields(builder: flatbuffers.Builder, associatedFieldsOffset: flatbuffers.Offset): void;
    static createAssociatedFieldsVector(builder: flatbuffers.Builder, data: number[] | Int32Array): flatbuffers.Offset;
    /**
     * @deprecated This Uint8Array overload will be removed in the future.
     */
    static createAssociatedFieldsVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startAssociatedFieldsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endCategoryRelationshipData(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createCategoryRelationshipData(builder: flatbuffers.Builder, categoriesOffset: flatbuffers.Offset, associatedFieldsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): CategoryRelationshipDataT;
    unpackTo(_o: CategoryRelationshipDataT): void;
}
export declare class CategoryRelationshipDataT implements flatbuffers.IGeneratedObject {
    categories: (number)[];
    associatedFields: (number)[];
    constructor(categories?: (number)[], associatedFields?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=category-relationship-data.d.ts.map