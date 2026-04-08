import { Sha256 } from './sha256';
export declare enum Digest {
    NONE = 0,
    Sha256 = 1
}
export declare function unionToDigest(type: Digest, accessor: (obj: Sha256) => Sha256 | null): Sha256 | null;
export declare function unionListToDigest(type: Digest, accessor: (index: number, obj: Sha256) => Sha256 | null, index: number): Sha256 | null;
//# sourceMappingURL=digest.d.ts.map