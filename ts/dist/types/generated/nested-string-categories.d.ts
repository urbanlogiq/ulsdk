import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { NestedStringCategoryNode, NestedStringCategoryNodeT } from './nested-string-category-node';
export declare class NestedStringCategories implements flatbuffers.IUnpackableObject<NestedStringCategoriesT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NestedStringCategories;
    static getRootAsNestedStringCategories(bb: flatbuffers.ByteBuffer, obj?: NestedStringCategories): NestedStringCategories;
    static getSizePrefixedRootAsNestedStringCategories(bb: flatbuffers.ByteBuffer, obj?: NestedStringCategories): NestedStringCategories;
    nestingTree(index: number, obj?: NestedStringCategoryNode): NestedStringCategoryNode | null;
    nestingTreeLength(): number;
    static startNestedStringCategories(builder: flatbuffers.Builder): void;
    static addNestingTree(builder: flatbuffers.Builder, nestingTreeOffset: flatbuffers.Offset): void;
    static createNestingTreeVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startNestingTreeVector(builder: flatbuffers.Builder, numElems: number): void;
    static endNestedStringCategories(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createNestedStringCategories(builder: flatbuffers.Builder, nestingTreeOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): NestedStringCategoriesT;
    unpackTo(_o: NestedStringCategoriesT): void;
}
export declare class NestedStringCategoriesT implements flatbuffers.IGeneratedObject {
    nestingTree: (NestedStringCategoryNodeT)[];
    constructor(nestingTree?: (NestedStringCategoryNodeT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=nested-string-categories.d.ts.map