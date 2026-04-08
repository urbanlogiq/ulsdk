import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { BinaryT } from './binary';
import { BinaryViewT } from './binary-view';
import { BoolT } from './bool';
import { DateT } from './date';
import { DecimalT } from './decimal';
import { DictionaryEncoding, DictionaryEncodingT } from './dictionary-encoding';
import { DurationT } from './duration';
import { FixedSizeBinaryT } from './fixed-size-binary';
import { FixedSizeListT } from './fixed-size-list';
import { FloatingPointT } from './floating-point';
import { IntT } from './int';
import { IntervalT } from './interval';
import { KeyValue, KeyValueT } from './key-value';
import { LargeBinaryT } from './large-binary';
import { LargeListT } from './large-list';
import { LargeListViewT } from './large-list-view';
import { LargeUtf8T } from './large-utf8';
import { ListT } from './list';
import { ListViewT } from './list-view';
import { MapT } from './map';
import { NullT } from './null';
import { RunEndEncodedT } from './run-end-encoded';
import { Struct_T } from './struct-';
import { TimeT } from './time';
import { TimestampT } from './timestamp';
import { Type } from './type';
import { UnionT } from './union';
import { Utf8T } from './utf8';
import { Utf8ViewT } from './utf8-view';
/**
 * ----------------------------------------------------------------------
 * A field represents a named column in a record / row batch or child of a
 * nested type.
 */
export declare class Field implements flatbuffers.IUnpackableObject<FieldT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Field;
    static getRootAsField(bb: flatbuffers.ByteBuffer, obj?: Field): Field;
    static getSizePrefixedRootAsField(bb: flatbuffers.ByteBuffer, obj?: Field): Field;
    /**
     * Name is not required, in i.e. a List
     */
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    /**
     * Whether or not this field can contain nulls. Should be true in general.
     */
    nullable(): boolean;
    typeType(): Type;
    /**
     * This is the type of the decoded value if the field is dictionary encoded.
     */
    type<T extends flatbuffers.Table>(obj: any): any | null;
    /**
     * Present only if the field is dictionary encoded.
     */
    dictionary(obj?: DictionaryEncoding): DictionaryEncoding | null;
    /**
     * children apply only to nested data types like Struct, List and Union. For
     * primitive types children will have length 0.
     */
    children(index: number, obj?: Field): Field | null;
    childrenLength(): number;
    /**
     * User-defined metadata
     */
    customMetadata(index: number, obj?: KeyValue): KeyValue | null;
    customMetadataLength(): number;
    static startField(builder: flatbuffers.Builder): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static addNullable(builder: flatbuffers.Builder, nullable: boolean): void;
    static addTypeType(builder: flatbuffers.Builder, typeType: Type): void;
    static addType(builder: flatbuffers.Builder, typeOffset: flatbuffers.Offset): void;
    static addDictionary(builder: flatbuffers.Builder, dictionaryOffset: flatbuffers.Offset): void;
    static addChildren(builder: flatbuffers.Builder, childrenOffset: flatbuffers.Offset): void;
    static createChildrenVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startChildrenVector(builder: flatbuffers.Builder, numElems: number): void;
    static addCustomMetadata(builder: flatbuffers.Builder, customMetadataOffset: flatbuffers.Offset): void;
    static createCustomMetadataVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startCustomMetadataVector(builder: flatbuffers.Builder, numElems: number): void;
    static endField(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): FieldT;
    unpackTo(_o: FieldT): void;
}
export declare class FieldT implements flatbuffers.IGeneratedObject {
    name: string | Uint8Array | null;
    nullable: boolean;
    typeType: Type;
    type: BinaryT | BinaryViewT | BoolT | DateT | DecimalT | DurationT | FixedSizeBinaryT | FixedSizeListT | FloatingPointT | IntT | IntervalT | LargeBinaryT | LargeListT | LargeListViewT | LargeUtf8T | ListT | ListViewT | MapT | NullT | RunEndEncodedT | Struct_T | TimeT | TimestampT | UnionT | Utf8T | Utf8ViewT | null;
    dictionary: DictionaryEncodingT | null;
    children: (FieldT)[];
    customMetadata: (KeyValueT)[];
    constructor(name?: string | Uint8Array | null, nullable?: boolean, typeType?: Type, type?: BinaryT | BinaryViewT | BoolT | DateT | DecimalT | DurationT | FixedSizeBinaryT | FixedSizeListT | FloatingPointT | IntT | IntervalT | LargeBinaryT | LargeListT | LargeListViewT | LargeUtf8T | ListT | ListViewT | MapT | NullT | RunEndEncodedT | Struct_T | TimeT | TimestampT | UnionT | Utf8T | Utf8ViewT | null, dictionary?: DictionaryEncodingT | null, children?: (FieldT)[], customMetadata?: (KeyValueT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=field.d.ts.map