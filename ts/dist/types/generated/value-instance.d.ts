import * as flatbuffers from 'flatbuffers/js/flatbuffers';
import { VArrayT } from './varray';
import { VBoolT } from './vbool';
import { VBytesT } from './vbytes';
import { VCharT } from './vchar';
import { VF32T } from './vf32';
import { VF64T } from './vf64';
import { VFixedSizeBytesT } from './vfixed-size-bytes';
import { VI16T } from './vi16';
import { VI32T } from './vi32';
import { VI64T } from './vi64';
import { VI8T } from './vi8';
import { VIsizeT } from './visize';
import { VNullT } from './vnull';
import { VPlaceholderT } from './vplaceholder';
import { VStrT } from './vstr';
import { VTimestampMsT } from './vtimestamp-ms';
import { VTimestampMsUtcT } from './vtimestamp-ms-utc';
import { VTimestampNsT } from './vtimestamp-ns';
import { VTimestampNsUtcT } from './vtimestamp-ns-utc';
import { VTri2DT } from './vtri2-d';
import { VU16T } from './vu16';
import { VU32T } from './vu32';
import { VU64T } from './vu64';
import { VU8T } from './vu8';
import { VUnitT } from './vunit';
import { VUsizeT } from './vusize';
import { Value } from './value';
export declare class ValueInstance implements flatbuffers.IUnpackableObject<ValueInstanceT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): ValueInstance;
    static getRootAsValueInstance(bb: flatbuffers.ByteBuffer, obj?: ValueInstance): ValueInstance;
    static getSizePrefixedRootAsValueInstance(bb: flatbuffers.ByteBuffer, obj?: ValueInstance): ValueInstance;
    vType(): Value;
    v<T extends flatbuffers.Table>(obj: any): any | null;
    name(): string | null;
    name(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    static startValueInstance(builder: flatbuffers.Builder): void;
    static addVType(builder: flatbuffers.Builder, vType: Value): void;
    static addV(builder: flatbuffers.Builder, vOffset: flatbuffers.Offset): void;
    static addName(builder: flatbuffers.Builder, nameOffset: flatbuffers.Offset): void;
    static endValueInstance(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createValueInstance(builder: flatbuffers.Builder, vType: Value, vOffset: flatbuffers.Offset, nameOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): ValueInstanceT;
    unpackTo(_o: ValueInstanceT): void;
}
export declare class ValueInstanceT implements flatbuffers.IGeneratedObject {
    vType: Value;
    v: VArrayT | VBoolT | VBytesT | VCharT | VF32T | VF64T | VFixedSizeBytesT | VI16T | VI32T | VI64T | VI8T | VIsizeT | VNullT | VPlaceholderT | VStrT | VTimestampMsT | VTimestampMsUtcT | VTimestampNsT | VTimestampNsUtcT | VTri2DT | VU16T | VU32T | VU64T | VU8T | VUnitT | VUsizeT | null;
    name: string | Uint8Array | null;
    constructor(vType?: Value, v?: VArrayT | VBoolT | VBytesT | VCharT | VF32T | VF64T | VFixedSizeBytesT | VI16T | VI32T | VI64T | VI8T | VIsizeT | VNullT | VPlaceholderT | VStrT | VTimestampMsT | VTimestampMsUtcT | VTimestampNsT | VTimestampNsUtcT | VTri2DT | VU16T | VU32T | VU64T | VU8T | VUnitT | VUsizeT | null, name?: string | Uint8Array | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=value-instance.d.ts.map