import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { CategoryRelationshipDataT } from './category-relationship-data';
import { HierarchyRelationshipDataT } from './hierarchy-relationship-data';
import { NestedCategoryRelationshipDataT } from './nested-category-relationship-data';
import { NestedHierarchyRelationshipDataT } from './nested-hierarchy-relationship-data';
import { UlFieldRelationshipData } from './ul-field-relationship-data';
export declare class UlFieldRelationship implements flatbuffers.IUnpackableObject<UlFieldRelationshipT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): UlFieldRelationship;
    static getRootAsUlFieldRelationship(bb: flatbuffers.ByteBuffer, obj?: UlFieldRelationship): UlFieldRelationship;
    static getSizePrefixedRootAsUlFieldRelationship(bb: flatbuffers.ByteBuffer, obj?: UlFieldRelationship): UlFieldRelationship;
    relationshipDisplayName(): string | null;
    relationshipDisplayName(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    relationshipDataType(): UlFieldRelationshipData;
    relationshipData<T extends flatbuffers.Table>(obj: any): any | null;
    static startUlFieldRelationship(builder: flatbuffers.Builder): void;
    static addRelationshipDisplayName(builder: flatbuffers.Builder, relationshipDisplayNameOffset: flatbuffers.Offset): void;
    static addRelationshipDataType(builder: flatbuffers.Builder, relationshipDataType: UlFieldRelationshipData): void;
    static addRelationshipData(builder: flatbuffers.Builder, relationshipDataOffset: flatbuffers.Offset): void;
    static endUlFieldRelationship(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createUlFieldRelationship(builder: flatbuffers.Builder, relationshipDisplayNameOffset: flatbuffers.Offset, relationshipDataType: UlFieldRelationshipData, relationshipDataOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): UlFieldRelationshipT;
    unpackTo(_o: UlFieldRelationshipT): void;
}
export declare class UlFieldRelationshipT implements flatbuffers.IGeneratedObject {
    relationshipDisplayName: string | Uint8Array | null;
    relationshipDataType: UlFieldRelationshipData;
    relationshipData: CategoryRelationshipDataT | HierarchyRelationshipDataT | NestedCategoryRelationshipDataT | NestedHierarchyRelationshipDataT | null;
    constructor(relationshipDisplayName?: string | Uint8Array | null, relationshipDataType?: UlFieldRelationshipData, relationshipData?: CategoryRelationshipDataT | HierarchyRelationshipDataT | NestedCategoryRelationshipDataT | NestedHierarchyRelationshipDataT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=ul-field-relationship.d.ts.map