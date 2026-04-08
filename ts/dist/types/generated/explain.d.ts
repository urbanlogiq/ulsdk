import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { ExplainFormat } from './explain-format';
export declare class Explain implements flatbuffers.IUnpackableObject<ExplainT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Explain;
    static getRootAsExplain(bb: flatbuffers.ByteBuffer, obj?: Explain): Explain;
    static getSizePrefixedRootAsExplain(bb: flatbuffers.ByteBuffer, obj?: Explain): Explain;
    format(): ExplainFormat;
    analyze(): boolean;
    verbose(): boolean;
    static startExplain(builder: flatbuffers.Builder): void;
    static addFormat(builder: flatbuffers.Builder, format: ExplainFormat): void;
    static addAnalyze(builder: flatbuffers.Builder, analyze: boolean): void;
    static addVerbose(builder: flatbuffers.Builder, verbose: boolean): void;
    static endExplain(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createExplain(builder: flatbuffers.Builder, format: ExplainFormat, analyze: boolean, verbose: boolean): flatbuffers.Offset;
    unpack(): ExplainT;
    unpackTo(_o: ExplainT): void;
}
export declare class ExplainT implements flatbuffers.IGeneratedObject {
    format: ExplainFormat;
    analyze: boolean;
    verbose: boolean;
    constructor(format?: ExplainFormat, analyze?: boolean, verbose?: boolean);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=explain.d.ts.map