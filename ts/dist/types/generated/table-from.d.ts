import { ObjectId } from './object-id';
import { Schema } from './schema';
export declare enum TableFrom {
    NONE = 0,
    ObjectId = 1,
    Schema = 2
}
export declare function unionToTableFrom(type: TableFrom, accessor: (obj: ObjectId | Schema) => ObjectId | Schema | null): ObjectId | Schema | null;
export declare function unionListToTableFrom(type: TableFrom, accessor: (index: number, obj: ObjectId | Schema) => ObjectId | Schema | null, index: number): ObjectId | Schema | null;
//# sourceMappingURL=table-from.d.ts.map