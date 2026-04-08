/**
 * The update cadence of the dataset. This looks at the maximum timestamp/observation date in the data,
 * and not when the pipeline ran because we can run a pipeline today that only ingests data from 2020.
 */
export declare enum UpdateCadence {
    UC_UNSET = 0,
    UC_IRREGULAR = 1,
    UC_DAILY = 2,
    UC_WEEKLY = 3,
    UC_BI_WEEKLY = 4,
    UC_MONTHLY = 5,
    UC_YEARLY = 6
}
//# sourceMappingURL=update-cadence.d.ts.map