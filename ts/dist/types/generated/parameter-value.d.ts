import { ByteArray } from './byte-array';
import { ObjectId } from './object-id';
import { ParameterFlags } from './parameter-flags';
import { ValueInstance } from './value-instance';
export declare enum ParameterValue {
    NONE = 0,
    ByteArray = 1,
    ObjectId = 2,
    ParameterFlags = 3,
    ValueInstance = 4
}
export declare function unionToParameterValue(type: ParameterValue, accessor: (obj: ByteArray | ObjectId | ParameterFlags | ValueInstance) => ByteArray | ObjectId | ParameterFlags | ValueInstance | null): ByteArray | ObjectId | ParameterFlags | ValueInstance | null;
export declare function unionListToParameterValue(type: ParameterValue, accessor: (index: number, obj: ByteArray | ObjectId | ParameterFlags | ValueInstance) => ByteArray | ObjectId | ParameterFlags | ValueInstance | null, index: number): ByteArray | ObjectId | ParameterFlags | ValueInstance | null;
//# sourceMappingURL=parameter-value.d.ts.map