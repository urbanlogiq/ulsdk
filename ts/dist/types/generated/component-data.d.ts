import { Dates } from './dates';
import { DatetimeRange } from './datetime-range';
import { FloatRange } from './float-range';
import { IntRange } from './int-range';
import { NestedStringCategories } from './nested-string-categories';
import { StringCategories } from './string-categories';
export declare enum ComponentData {
    NONE = 0,
    StringCategories = 1,
    IntRange = 2,
    FloatRange = 3,
    DatetimeRange = 4,
    Dates = 5,
    NestedStringCategories = 6
}
export declare function unionToComponentData(type: ComponentData, accessor: (obj: Dates | DatetimeRange | FloatRange | IntRange | NestedStringCategories | StringCategories) => Dates | DatetimeRange | FloatRange | IntRange | NestedStringCategories | StringCategories | null): Dates | DatetimeRange | FloatRange | IntRange | NestedStringCategories | StringCategories | null;
export declare function unionListToComponentData(type: ComponentData, accessor: (index: number, obj: Dates | DatetimeRange | FloatRange | IntRange | NestedStringCategories | StringCategories) => Dates | DatetimeRange | FloatRange | IntRange | NestedStringCategories | StringCategories | null, index: number): Dates | DatetimeRange | FloatRange | IntRange | NestedStringCategories | StringCategories | null;
//# sourceMappingURL=component-data.d.ts.map