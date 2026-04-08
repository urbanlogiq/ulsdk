import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { AggregationTy } from './aggregation-ty';
import { ChartTypeTy } from './chart-type-ty';
import { ObjectId, ObjectIdT } from './object-id';
import { ValuesFormatTy } from './values-format-ty';
export declare class TileSettings implements flatbuffers.IUnpackableObject<TileSettingsT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): TileSettings;
    static getRootAsTileSettings(bb: flatbuffers.ByteBuffer, obj?: TileSettings): TileSettings;
    static getSizePrefixedRootAsTileSettings(bb: flatbuffers.ByteBuffer, obj?: TileSettings): TileSettings;
    /**
     * The column of tbe aggregation dataset to use
     */
    aggregation(): AggregationTy;
    /**
     * The category
     */
    category(): number;
    /**
     * What chart type to display the data as
     */
    chartType(): ChartTypeTy;
    /**
     * The field name from the metadata and dataset. Note that if it is a
     * relationshipField, it will use the displayName instead
     */
    fieldName(): string | null;
    fieldName(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    /**
     * Whether to group the other fields under "Other" if not showing all columns
     */
    groupOthers(): boolean;
    /**
     * Whether it is a relationship field (or a non-associated field)
     */
    isRelationshipField(): boolean;
    /**
     * The metadata id for the field shown
     */
    metadataId(obj?: ObjectId): ObjectId | null;
    /**
     * Which output stream the report belongs to
     */
    outputStreamIndex(): number;
    /**
     * Which columns the user has selected to show. If this is a relationship field, the user
     * can select which of the relationship fields to show. If it is nonassociated field, it's
     * possible that they only want to show certain ranges, which would be stored here, but
     * that isn't currently supported
     */
    selectedColumns(index: number): string;
    selectedColumns(index: number, optionalEncoding: flatbuffers.Encoding): string | Uint8Array;
    selectedColumnsLength(): number;
    /**
     * The title of the tile
     */
    title(): string | null;
    title(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    /**
     * Percentage or RawNumber
     */
    valuesFormat(): ValuesFormatTy;
    /**
     * Record-count tiles report on the total number of graph nodes for the stream in the area, rather than
     * on any specific field in that stream.
     */
    isRecordCountTile(): boolean;
    /**
     * Font size for text tiles
     */
    textTileFontSize(): number;
    recordCountStreamId(obj?: ObjectId): ObjectId | null;
    static startTileSettings(builder: flatbuffers.Builder): void;
    static addAggregation(builder: flatbuffers.Builder, aggregation: AggregationTy): void;
    static addCategory(builder: flatbuffers.Builder, category: number): void;
    static addChartType(builder: flatbuffers.Builder, chartType: ChartTypeTy): void;
    static addFieldName(builder: flatbuffers.Builder, fieldNameOffset: flatbuffers.Offset): void;
    static addGroupOthers(builder: flatbuffers.Builder, groupOthers: boolean): void;
    static addIsRelationshipField(builder: flatbuffers.Builder, isRelationshipField: boolean): void;
    static addMetadataId(builder: flatbuffers.Builder, metadataIdOffset: flatbuffers.Offset): void;
    static addOutputStreamIndex(builder: flatbuffers.Builder, outputStreamIndex: number): void;
    static addSelectedColumns(builder: flatbuffers.Builder, selectedColumnsOffset: flatbuffers.Offset): void;
    static createSelectedColumnsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startSelectedColumnsVector(builder: flatbuffers.Builder, numElems: number): void;
    static addTitle(builder: flatbuffers.Builder, titleOffset: flatbuffers.Offset): void;
    static addValuesFormat(builder: flatbuffers.Builder, valuesFormat: ValuesFormatTy): void;
    static addIsRecordCountTile(builder: flatbuffers.Builder, isRecordCountTile: boolean): void;
    static addTextTileFontSize(builder: flatbuffers.Builder, textTileFontSize: number): void;
    static addRecordCountStreamId(builder: flatbuffers.Builder, recordCountStreamIdOffset: flatbuffers.Offset): void;
    static endTileSettings(builder: flatbuffers.Builder): flatbuffers.Offset;
    unpack(): TileSettingsT;
    unpackTo(_o: TileSettingsT): void;
}
export declare class TileSettingsT implements flatbuffers.IGeneratedObject {
    aggregation: AggregationTy;
    category: number;
    chartType: ChartTypeTy;
    fieldName: string | Uint8Array | null;
    groupOthers: boolean;
    isRelationshipField: boolean;
    metadataId: ObjectIdT | null;
    outputStreamIndex: number;
    selectedColumns: (string)[];
    title: string | Uint8Array | null;
    valuesFormat: ValuesFormatTy;
    isRecordCountTile: boolean;
    textTileFontSize: number;
    recordCountStreamId: ObjectIdT | null;
    constructor(aggregation?: AggregationTy, category?: number, chartType?: ChartTypeTy, fieldName?: string | Uint8Array | null, groupOthers?: boolean, isRelationshipField?: boolean, metadataId?: ObjectIdT | null, outputStreamIndex?: number, selectedColumns?: (string)[], title?: string | Uint8Array | null, valuesFormat?: ValuesFormatTy, isRecordCountTile?: boolean, textTileFontSize?: number, recordCountStreamId?: ObjectIdT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=tile-settings.d.ts.map