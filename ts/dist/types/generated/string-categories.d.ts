import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class StringCategories implements flatbuffers.IUnpackableObject<StringCategoriesT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): StringCategories;
    static getRootAsStringCategories(bb: flatbuffers.ByteBuffer, obj?: StringCategories): StringCategories;
    static getSizePrefixedRootAsStringCategories(bb: flatbuffers.ByteBuffer, obj?: StringCategories): StringCategories;
    categories(index: number): string;
    categories(index: number, optionalEncoding: flatbuffers.Encoding): string | Uint8Array;
    categoriesLength(): number;
    static startStringCategories(builder: flatbuffers.Builder): void;
    static addCategories(builder: flatbuffers.Builder, categoriesOffset: flatbuffers.Offset): void;
    static createCategoriesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startCategoriesVector(builder: flatbuffers.Builder, numElems: number): void;
    static endStringCategories(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createStringCategories(builder: flatbuffers.Builder, categoriesOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): StringCategoriesT;
    unpackTo(_o: StringCategoriesT): void;
}
export declare class StringCategoriesT implements flatbuffers.IGeneratedObject {
    categories: (string)[];
    constructor(categories?: (string)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=string-categories.d.ts.map