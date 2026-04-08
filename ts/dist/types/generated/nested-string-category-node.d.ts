import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class NestedStringCategoryNode implements flatbuffers.IUnpackableObject<NestedStringCategoryNodeT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): NestedStringCategoryNode;
    static getRootAsNestedStringCategoryNode(bb: flatbuffers.ByteBuffer, obj?: NestedStringCategoryNode): NestedStringCategoryNode;
    static getSizePrefixedRootAsNestedStringCategoryNode(bb: flatbuffers.ByteBuffer, obj?: NestedStringCategoryNode): NestedStringCategoryNode;
    value(): string | null;
    value(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    childValues(index: number): string;
    childValues(index: number, optionalEncoding: flatbuffers.Encoding): string | Uint8Array;
    childValuesLength(): number;
    static startNestedStringCategoryNode(builder: flatbuffers.Builder): void;
    static addValue(builder: flatbuffers.Builder, valueOffset: flatbuffers.Offset): void;
    static addChildValues(builder: flatbuffers.Builder, childValuesOffset: flatbuffers.Offset): void;
    static createChildValuesVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startChildValuesVector(builder: flatbuffers.Builder, numElems: number): void;
    static endNestedStringCategoryNode(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createNestedStringCategoryNode(builder: flatbuffers.Builder, valueOffset: flatbuffers.Offset, childValuesOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): NestedStringCategoryNodeT;
    unpackTo(_o: NestedStringCategoryNodeT): void;
}
export declare class NestedStringCategoryNodeT implements flatbuffers.IGeneratedObject {
    value: string | Uint8Array | null;
    childValues: (string)[];
    constructor(value?: string | Uint8Array | null, childValues?: (string)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=nested-string-category-node.d.ts.map