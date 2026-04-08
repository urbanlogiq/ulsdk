import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { EdgeQueryT } from './edge-query';
import { NodeQueryT } from './node-query';
import { QueryPathElementUnion } from './query-path-element-union';
export declare class QueryPathElement implements flatbuffers.IUnpackableObject<QueryPathElementT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): QueryPathElement;
    static getRootAsQueryPathElement(bb: flatbuffers.ByteBuffer, obj?: QueryPathElement): QueryPathElement;
    static getSizePrefixedRootAsQueryPathElement(bb: flatbuffers.ByteBuffer, obj?: QueryPathElement): QueryPathElement;
    elementType(): QueryPathElementUnion;
    element<T extends flatbuffers.Table>(obj: any): any | null;
    static startQueryPathElement(builder: flatbuffers.Builder): void;
    static addElementType(builder: flatbuffers.Builder, elementType: QueryPathElementUnion): void;
    static addElement(builder: flatbuffers.Builder, elementOffset: flatbuffers.Offset): void;
    static endQueryPathElement(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createQueryPathElement(builder: flatbuffers.Builder, elementType: QueryPathElementUnion, elementOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): QueryPathElementT;
    unpackTo(_o: QueryPathElementT): void;
}
export declare class QueryPathElementT implements flatbuffers.IGeneratedObject {
    elementType: QueryPathElementUnion;
    element: EdgeQueryT | NodeQueryT | null;
    constructor(elementType?: QueryPathElementUnion, element?: EdgeQueryT | NodeQueryT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=query-path-element.d.ts.map