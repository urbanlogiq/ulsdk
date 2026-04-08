import { CategoryRelationshipData } from './category-relationship-data';
import { HierarchyRelationshipData } from './hierarchy-relationship-data';
import { NestedCategoryRelationshipData } from './nested-category-relationship-data';
import { NestedHierarchyRelationshipData } from './nested-hierarchy-relationship-data';
export declare enum UlFieldRelationshipData {
    NONE = 0,
    HierarchyRelationshipData = 1,
    CategoryRelationshipData = 2,
    NestedCategoryRelationshipData = 3,
    NestedHierarchyRelationshipData = 4
}
export declare function unionToUlFieldRelationshipData(type: UlFieldRelationshipData, accessor: (obj: CategoryRelationshipData | HierarchyRelationshipData | NestedCategoryRelationshipData | NestedHierarchyRelationshipData) => CategoryRelationshipData | HierarchyRelationshipData | NestedCategoryRelationshipData | NestedHierarchyRelationshipData | null): CategoryRelationshipData | HierarchyRelationshipData | NestedCategoryRelationshipData | NestedHierarchyRelationshipData | null;
export declare function unionListToUlFieldRelationshipData(type: UlFieldRelationshipData, accessor: (index: number, obj: CategoryRelationshipData | HierarchyRelationshipData | NestedCategoryRelationshipData | NestedHierarchyRelationshipData) => CategoryRelationshipData | HierarchyRelationshipData | NestedCategoryRelationshipData | NestedHierarchyRelationshipData | null, index: number): CategoryRelationshipData | HierarchyRelationshipData | NestedCategoryRelationshipData | NestedHierarchyRelationshipData | null;
//# sourceMappingURL=ul-field-relationship-data.d.ts.map