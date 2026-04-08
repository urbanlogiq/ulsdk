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
export declare class Attr implements flatbuffers.IUnpackableObject<AttrT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): Attr;
    static getRootAsAttr(bb: flatbuffers.ByteBuffer, obj?: Attr): Attr;
    static getSizePrefixedRootAsAttr(bb: flatbuffers.ByteBuffer, obj?: Attr): Attr;
    key(): string | null;
    key(optionalEncoding: flatbuffers.Encoding): string | Uint8Array | null;
    vType(): Value;
    v<T extends flatbuffers.Table>(obj: any): any | null;
    static startAttr(builder: flatbuffers.Builder): void;
    static addKey(builder: flatbuffers.Builder, keyOffset: flatbuffers.Offset): void;
    static addVType(builder: flatbuffers.Builder, vType: Value): void;
    static addV(builder: flatbuffers.Builder, vOffset: flatbuffers.Offset): void;
    static endAttr(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createAttr(builder: flatbuffers.Builder, keyOffset: flatbuffers.Offset, vType: Value, vOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): AttrT;
    unpackTo(_o: AttrT): void;
}
export declare class AttrT implements flatbuffers.IGeneratedObject {
    key: string | Uint8Array | null;
    vType: Value;
    v: VArrayT | VBoolT | VBytesT | VCharT | VF32T | VF64T | VFixedSizeBytesT | VI16T | VI32T | VI64T | VI8T | VIsizeT | VNullT | VPlaceholderT | VStrT | VTimestampMsT | VTimestampMsUtcT | VTimestampNsT | VTimestampNsUtcT | VTri2DT | VU16T | VU32T | VU64T | VU8T | VUnitT | VUsizeT | null;
    constructor(key?: string | Uint8Array | null, vType?: Value, v?: VArrayT | VBoolT | VBytesT | VCharT | VF32T | VF64T | VFixedSizeBytesT | VI16T | VI32T | VI64T | VI8T | VIsizeT | VNullT | VPlaceholderT | VStrT | VTimestampMsT | VTimestampMsUtcT | VTimestampNsT | VTimestampNsUtcT | VTri2DT | VU16T | VU32T | VU64T | VU8T | VUnitT | VUsizeT | null);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
//# sourceMappingURL=attr.d.ts.map