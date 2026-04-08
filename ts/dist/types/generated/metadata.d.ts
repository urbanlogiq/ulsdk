import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { DatacatalogGeometryT } from './datacatalog-geometry';
import { DatasetCategory } from './dataset-category';
import { DatasetSource, DatasetSourceT } from './dataset-source';
import { EntityTy } from './entity-ty';
import { GeometrySource } from './geometry-source';
import { NoGeometryT } from './no-geometry';
import { UlField, UlFieldT } from './ul-field';
import { UlFieldRelationship, UlFieldRelationshipT } from './ul-field-relationship';
import { UpdateCadence } from './update-cadence';
import { WorldGraphGeometryT } from './world-graph-geometry';
export declare class Metadata implements flatbuffers.IUnpackableObject<MetadataT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Metadata;
    static getRootAsMetadata(bb: flatbuffers.ByteBuffer, obj?: Metadata): Metadata;
    static getSizePrefixedRootAsMetadata(bb: flatbuffers.ByteBuffer, obj?: Metadata): Metadata;
    displayName(): string | null;
    displayName(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    description(): string | null;
    description(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    fields(index: number, obj?: UlField): UlField | null;
    fieldsLength(): number;
    summary(index: number): number | null;
    summaryLength(): number;
    summaryArray(): Int32Array | null;
    /**
     * Organizational category for frontend. Defaults to DC_HIDDEN.
     */
    datasetCategory(): DatasetCategory;
    /**
     * Field groupings e.g. age ranges, ethnicities or hierarchical codes like zoning and NAICS
     */
    fieldRelationships(index: number, obj?: UlFieldRelationship): UlFieldRelationship | null;
    fieldRelationshipsLength(): number;
    /**
     * An optional field that is meant to provide information to the user on
     * where the data has come from
     */
    source(obj?: DatasetSource): DatasetSource | null;
    geometrySourceType(): GeometrySource;
    geometrySource<T extends flatbuffers.Table>(obj: any): any | null;
    /**
     * is to be included in the boundary selection modal
     */
    areaSelection(): boolean;
    /**
     * do not use user's viewport bounding box when fetching this stream's geometry from worldgraph
     */
    doNotFilterGeometryByViewport(): boolean;
    entityTy(): EntityTy;
    updateCadence(): UpdateCadence;
    /**
     * Many geospatial datasets whose rows correspond to map locations have a
     * column that should be used as the human-friendly display name of the location.
     * For example, for a stream containing stores, this field might be "store_name".
     * If the stream contains multiple rows with the same ul_node_id, then those rows
     * should have the same value for the location_description_field.
     * This attribute holds the index of the field in the dataset that should be
     * used as the location description.
     */
    locationDescriptionField(): number;
    static startMetadata(builder: flatbuffers.Builder): void;
    static addDisplayName(builder: flatbuffers.Builder, displayNameOffset: flatbuffers.Offset): void;
    static addDescription(builder: flatbuffers.Builder, descriptionOffset: flatbuffers.Offset): void;
    static addFields(builder: flatbuffers.Builder, fieldsOffset: flatbuffers.Offset): void;
    static createFieldsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startFieldsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addSummary(builder: flatbuffers.Builder, summaryOffset: flatbuffers.Offset): void;
    static createSummaryVector(builder: flatbuffers.Builder, data: number[] | Int32Array): flatbuffers.Offset;
    /**
     * @deprecated This Uint8Array overload will be removed in the future.
     */
    static createSummaryVector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static startSummaryVector(builder: flatbuffers.Builder, numElems: number): void;
    static addDatasetCategory(builder: flatbuffers.Builder, datasetCategory: DatasetCategory): void;
    static addFieldRelationships(builder: flatbuffers.Builder, fieldRelationshipsOffset: flatbuffers.Offset): void;
    static createFieldRelationshipsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startFieldRelationshipsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addSource(builder: flatbuffers.Builder, sourceOffset: flatbuffers.Offset): void;
    static addGeometrySourceType(builder: flatbuffers.Builder, geometrySourceType: GeometrySource): void;
    static addGeometrySource(builder: flatbuffers.Builder, geometrySourceOffset: flatbuffers.Offset): void;
    static addAreaSelection(builder: flatbuffers.Builder, areaSelection: boolean): void;
    static addDoNotFilterGeometryByViewport(builder: flatbuffers.Builder, doNotFilterGeometryByViewport: boolean): void;
    static addEntityTy(builder: flatbuffers.Builder, entityTy: EntityTy): void;
    static addUpdateCadence(builder: flatbuffers.Builder, updateCadence: UpdateCadence): void;
    static addLocationDescriptionField(builder: flatbuffers.Builder, locationDescriptionField: number): void;
    static endMetadata(builder: flatbuffers.Builder): flatbuffers.Offset;
    static finishMetadataBuffer(builder: flatbuffers.Builder, offset: flatbuffers.Offset): void;
    static finishSizePrefixedMetadataBuffer(builder: flatbuffers.Builder, offset: flatbuffers.Offset): void;
    unpack(): MetadataT;
    unpackTo(_o: MetadataT): void;
}
export declare class MetadataT implements flatbuffers.IGeneratedObject {
    displayName: string | Uint8Array | null;
    description: string | Uint8Array | null;
    fields: (UlFieldT)[];
    summary: (number)[];
    datasetCategory: DatasetCategory;
    fieldRelationships: (UlFieldRelationshipT)[];
    source: DatasetSourceT | null;
    geometrySourceType: GeometrySource;
    geometrySource: DatacatalogGeometryT | NoGeometryT | WorldGraphGeometryT | null;
    areaSelection: boolean;
    doNotFilterGeometryByViewport: boolean;
    entityTy: EntityTy;
    updateCadence: UpdateCadence;
    locationDescriptionField: number;
    constructor(displayName?: string | Uint8Array | null, description?: string | Uint8Array | null, fields?: (UlFieldT)[], summary?: (number)[], datasetCategory?: DatasetCategory, fieldRelationships?: (UlFieldRelationshipT)[], source?: DatasetSourceT | null, geometrySourceType?: GeometrySource, geometrySource?: DatacatalogGeometryT | NoGeometryT | WorldGraphGeometryT | null, areaSelection?: boolean, doNotFilterGeometryByViewport?: boolean, entityTy?: EntityTy, updateCadence?: UpdateCadence, locationDescriptionField?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=metadata.d.ts.map