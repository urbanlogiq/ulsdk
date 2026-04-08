import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class DatasetSource implements flatbuffers.IUnpackableObject<DatasetSourceT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DatasetSource;
    static getRootAsDatasetSource(bb: flatbuffers.ByteBuffer, obj?: DatasetSource): DatasetSource;
    static getSizePrefixedRootAsDatasetSource(bb: flatbuffers.ByteBuffer, obj?: DatasetSource): DatasetSource;
    /**
     * The entity that created the data (Manifold, Government of Canada, Wejo, City
     */
    source(): string | null;
    source(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    /**
     * A URL to where the data set can be fetched. Ideally a direct download but
     */
    url(): string | null;
    url(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    /**
     * Date information about the data source, such as the year it was generated.
     * This is a free-form text field that isn't interpreted in any means by the
     * system.
     */
    date(): string | null;
    date(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startDatasetSource(builder: flatbuffers.Builder): void;
    static addSource(builder: flatbuffers.Builder, sourceOffset: flatbuffers.Offset): void;
    static addUrl(builder: flatbuffers.Builder, urlOffset: flatbuffers.Offset): void;
    static addDate(builder: flatbuffers.Builder, dateOffset: flatbuffers.Offset): void;
    static endDatasetSource(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDatasetSource(builder: flatbuffers.Builder, sourceOffset: flatbuffers.Offset, urlOffset: flatbuffers.Offset, dateOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DatasetSourceT;
    unpackTo(_o: DatasetSourceT): void;
}
export declare class DatasetSourceT implements flatbuffers.IGeneratedObject {
    source: string | Uint8Array | null;
    url: string | Uint8Array | null;
    date: string | Uint8Array | null;
    constructor(source?: string | Uint8Array | null, url?: string | Uint8Array | null, date?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=dataset-source.d.ts.map