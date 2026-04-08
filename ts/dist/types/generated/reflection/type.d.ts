import * as flatbuffers from 'flatbuffers';
import { BaseType } from '../reflection/base-type';
export declare class Type implements flatbuffers.IUnpackableObject<TypeT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Type;
    static getRootAsType(bb: flatbuffers.ByteBuffer, obj?: Type): Type;
    static getSizePrefixedRootAsType(bb: flatbuffers.ByteBuffer, obj?: Type): Type;
    baseType(): BaseType;
    element(): BaseType;
    index(): number;
    fixedLength(): number;
    /**
     * The size (octets) of the `base_type` field.
     */
    baseSize(): number;
    /**
     * The size (octets) of the `element` field, if present.
     */
    elementSize(): number;
    static startType(builder: flatbuffers.Builder): void;
    static addBaseType(builder: flatbuffers.Builder, baseType: BaseType): void;
    static addElement(builder: flatbuffers.Builder, element: BaseType): void;
    static addIndex(builder: flatbuffers.Builder, index: number): void;
    static addFixedLength(builder: flatbuffers.Builder, fixedLength: number): void;
    static addBaseSize(builder: flatbuffers.Builder, baseSize: number): void;
    static addElementSize(builder: flatbuffers.Builder, elementSize: number): void;
    static endType(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createType(builder: flatbuffers.Builder, baseType: BaseType, element: BaseType, index: number, fixedLength: number, baseSize: number, elementSize: number): flatbuffers.Offset;
    unpack(): TypeT;
    unpackTo(_o: TypeT): void;
}
export declare class TypeT implements flatbuffers.IGeneratedObject {
    baseType: BaseType;
    element: BaseType;
    index: number;
    fixedLength: number;
    baseSize: number;
    elementSize: number;
    constructor(baseType?: BaseType, element?: BaseType, index?: number, fixedLength?: number, baseSize?: number, elementSize?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=type.d.ts.map