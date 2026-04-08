import { Binary } from './binary';
import { BinaryView } from './binary-view';
import { Bool } from './bool';
import { Date } from './date';
import { Decimal } from './decimal';
import { Duration } from './duration';
import { FixedSizeBinary } from './fixed-size-binary';
import { FixedSizeList } from './fixed-size-list';
import { FloatingPoint } from './floating-point';
import { Int } from './int';
import { Interval } from './interval';
import { LargeBinary } from './large-binary';
import { LargeList } from './large-list';
import { LargeListView } from './large-list-view';
import { LargeUtf8 } from './large-utf8';
import { List } from './list';
import { ListView } from './list-view';
import { Map } from './map';
import { Null } from './null';
import { RunEndEncoded } from './run-end-encoded';
import { Struct_ } from './struct-';
import { Time } from './time';
import { Timestamp } from './timestamp';
import { Union } from './union';
import { Utf8 } from './utf8';
import { Utf8View } from './utf8-view';
/**
 * ----------------------------------------------------------------------
 * Top-level Type value, enabling extensible type-specific metadata. We can
 * add new logical types to Type without breaking backwards compatibility
 */
export declare enum Type {
    NONE = 0,
    Null = 1,
    Int = 2,
    FloatingPoint = 3,
    Binary = 4,
    Utf8 = 5,
    Bool = 6,
    Decimal = 7,
    Date = 8,
    Time = 9,
    Timestamp = 10,
    Interval = 11,
    List = 12,
    Struct_ = 13,
    Union = 14,
    FixedSizeBinary = 15,
    FixedSizeList = 16,
    Map = 17,
    Duration = 18,
    LargeBinary = 19,
    LargeUtf8 = 20,
    LargeList = 21,
    RunEndEncoded = 22,
    BinaryView = 23,
    Utf8View = 24,
    ListView = 25,
    LargeListView = 26
}
export declare function unionToType(type: Type, accessor: (obj: Binary | BinaryView | Bool | Date | Decimal | Duration | FixedSizeBinary | FixedSizeList | FloatingPoint | Int | Interval | LargeBinary | LargeList | LargeListView | LargeUtf8 | List | ListView | Map | Null | RunEndEncoded | Struct_ | Time | Timestamp | Union | Utf8 | Utf8View) => Binary | BinaryView | Bool | Date | Decimal | Duration | FixedSizeBinary | FixedSizeList | FloatingPoint | Int | Interval | LargeBinary | LargeList | LargeListView | LargeUtf8 | List | ListView | Map | Null | RunEndEncoded | Struct_ | Time | Timestamp | Union | Utf8 | Utf8View | null): Binary | BinaryView | Bool | Date | Decimal | Duration | FixedSizeBinary | FixedSizeList | FloatingPoint | Int | Interval | LargeBinary | LargeList | LargeListView | LargeUtf8 | List | ListView | Map | Null | RunEndEncoded | Struct_ | Time | Timestamp | Union | Utf8 | Utf8View | null;
export declare function unionListToType(type: Type, accessor: (index: number, obj: Binary | BinaryView | Bool | Date | Decimal | Duration | FixedSizeBinary | FixedSizeList | FloatingPoint | Int | Interval | LargeBinary | LargeList | LargeListView | LargeUtf8 | List | ListView | Map | Null | RunEndEncoded | Struct_ | Time | Timestamp | Union | Utf8 | Utf8View) => Binary | BinaryView | Bool | Date | Decimal | Duration | FixedSizeBinary | FixedSizeList | FloatingPoint | Int | Interval | LargeBinary | LargeList | LargeListView | LargeUtf8 | List | ListView | Map | Null | RunEndEncoded | Struct_ | Time | Timestamp | Union | Utf8 | Utf8View | null, index: number): Binary | BinaryView | Bool | Date | Decimal | Duration | FixedSizeBinary | FixedSizeList | FloatingPoint | Int | Interval | LargeBinary | LargeList | LargeListView | LargeUtf8 | List | ListView | Map | Null | RunEndEncoded | Struct_ | Time | Timestamp | Union | Utf8 | Utf8View | null;
//# sourceMappingURL=type.d.ts.map