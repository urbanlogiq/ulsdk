import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { SetExpr, SetExprT } from './set-expr';
/**
 * On conflict, update values according to the expressions provided; this
 * is equivalent to an `upsert` operation.
 */
export declare class DoUpdate implements flatbuffers.IUnpackableObject<DoUpdateT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): DoUpdate;
    static getRootAsDoUpdate(bb: flatbuffers.ByteBuffer, obj?: DoUpdate): DoUpdate;
    static getSizePrefixedRootAsDoUpdate(bb: flatbuffers.ByteBuffer, obj?: DoUpdate): DoUpdate;
    assignments(index: number, obj?: SetExpr): SetExpr | null;
    assignmentsLength(): number;
    static startDoUpdate(builder: flatbuffers.Builder): void;
    static addAssignments(builder: flatbuffers.Builder, assignmentsOffset: flatbuffers.Offset): void;
    static createAssignmentsVector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static startAssignmentsVector(builder: flatbuffers.Builder, numElems: number): void;
    static endDoUpdate(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createDoUpdate(builder: flatbuffers.Builder, assignmentsOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DoUpdateT;
    unpackTo(_o: DoUpdateT): void;
}
export declare class DoUpdateT implements flatbuffers.IGeneratedObject {
    assignments: (SetExprT)[];
    constructor(assignments?: (SetExprT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=do-update.d.ts.map