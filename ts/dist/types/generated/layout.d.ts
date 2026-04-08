import * as flatbuffers from 'flatbuffers/js/flatbuffers';
export declare class Layout implements flatbuffers.IUnpackableObject<LayoutT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Layout;
    static getRootAsLayout(bb: flatbuffers.ByteBuffer, obj?: Layout): Layout;
    static getSizePrefixedRootAsLayout(bb: flatbuffers.ByteBuffer, obj?: Layout): Layout;
    /**
     * The height of the chart tile in react-grid-layout grid units
     */
    height(): number;
    /**
     * The width in react-grid-layout grid units
     */
    width(): number;
    /**
     * The x position in react-grid-layout grid units
     */
    x(): number;
    /**
     * The y position in react-grid-layout grid units
     */
    y(): number;
    static startLayout(builder: flatbuffers.Builder): void;
    static addHeight(builder: flatbuffers.Builder, height: number): void;
    static addWidth(builder: flatbuffers.Builder, width: number): void;
    static addX(builder: flatbuffers.Builder, x: number): void;
    static addY(builder: flatbuffers.Builder, y: number): void;
    static endLayout(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createLayout(builder: flatbuffers.Builder, height: number, width: number, x: number, y: number): flatbuffers.Offset;
    unpack(): LayoutT;
    unpackTo(_o: LayoutT): void;
}
export declare class LayoutT implements flatbuffers.IGeneratedObject {
    height: number;
    width: number;
    x: number;
    y: number;
    constructor(height?: number, width?: number, x?: number, y?: number);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=layout.d.ts.map