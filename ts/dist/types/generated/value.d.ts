import { VArray } from './varray';
import { VBool } from './vbool';
import { VBytes } from './vbytes';
import { VChar } from './vchar';
import { VF32 } from './vf32';
import { VF64 } from './vf64';
import { VFixedSizeBytes } from './vfixed-size-bytes';
import { VI16 } from './vi16';
import { VI32 } from './vi32';
import { VI64 } from './vi64';
import { VI8 } from './vi8';
import { VIsize } from './visize';
import { VNull } from './vnull';
import { VPlaceholder } from './vplaceholder';
import { VStr } from './vstr';
import { VTimestampMs } from './vtimestamp-ms';
import { VTimestampMsUtc } from './vtimestamp-ms-utc';
import { VTimestampNs } from './vtimestamp-ns';
import { VTimestampNsUtc } from './vtimestamp-ns-utc';
import { VTri2D } from './vtri2-d';
import { VU16 } from './vu16';
import { VU32 } from './vu32';
import { VU64 } from './vu64';
import { VU8 } from './vu8';
import { VUnit } from './vunit';
import { VUsize } from './vusize';
export declare enum Value {
    NONE = 0,
    VBool = 1,
    VUnit = 2,
    VChar = 3,
    VNull = 4,
    VI8 = 5,
    VU8 = 6,
    VI16 = 7,
    VU16 = 8,
    VI32 = 9,
    VU32 = 10,
    VF32 = 11,
    VIsize = 12,
    VUsize = 13,
    VI64 = 14,
    VU64 = 15,
    VF64 = 16,
    VStr = 17,
    VBytes = 18,
    VArray = 19,
    VTri2D = 20,
    VFixedSizeBytes = 21,
    VTimestampMsUtc = 22,
    VTimestampMs = 23,
    VTimestampNsUtc = 24,
    VTimestampNs = 25,
    VPlaceholder = 26
}
export declare function unionToValue(type: Value, accessor: (obj: VArray | VBool | VBytes | VChar | VF32 | VF64 | VFixedSizeBytes | VI16 | VI32 | VI64 | VI8 | VIsize | VNull | VPlaceholder | VStr | VTimestampMs | VTimestampMsUtc | VTimestampNs | VTimestampNsUtc | VTri2D | VU16 | VU32 | VU64 | VU8 | VUnit | VUsize) => VArray | VBool | VBytes | VChar | VF32 | VF64 | VFixedSizeBytes | VI16 | VI32 | VI64 | VI8 | VIsize | VNull | VPlaceholder | VStr | VTimestampMs | VTimestampMsUtc | VTimestampNs | VTimestampNsUtc | VTri2D | VU16 | VU32 | VU64 | VU8 | VUnit | VUsize | null): VArray | VBool | VBytes | VChar | VF32 | VF64 | VFixedSizeBytes | VI16 | VI32 | VI64 | VI8 | VIsize | VNull | VPlaceholder | VStr | VTimestampMs | VTimestampMsUtc | VTimestampNs | VTimestampNsUtc | VTri2D | VU16 | VU32 | VU64 | VU8 | VUnit | VUsize | null;
export declare function unionListToValue(type: Value, accessor: (index: number, obj: VArray | VBool | VBytes | VChar | VF32 | VF64 | VFixedSizeBytes | VI16 | VI32 | VI64 | VI8 | VIsize | VNull | VPlaceholder | VStr | VTimestampMs | VTimestampMsUtc | VTimestampNs | VTimestampNsUtc | VTri2D | VU16 | VU32 | VU64 | VU8 | VUnit | VUsize) => VArray | VBool | VBytes | VChar | VF32 | VF64 | VFixedSizeBytes | VI16 | VI32 | VI64 | VI8 | VIsize | VNull | VPlaceholder | VStr | VTimestampMs | VTimestampMsUtc | VTimestampNs | VTimestampNsUtc | VTri2D | VU16 | VU32 | VU64 | VU8 | VUnit | VUsize | null, index: number): VArray | VBool | VBytes | VChar | VF32 | VF64 | VFixedSizeBytes | VI16 | VI32 | VI64 | VI8 | VIsize | VNull | VPlaceholder | VStr | VTimestampMs | VTimestampMsUtc | VTimestampNs | VTimestampNsUtc | VTri2D | VU16 | VU32 | VU64 | VU8 | VUnit | VUsize | null;
//# sourceMappingURL=value.d.ts.map