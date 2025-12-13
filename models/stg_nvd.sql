WITH raw_data AS (
    SELECT 
        cve.id AS cve_id,
        cve.descriptions[OFFSET(0)].value AS description,
        cve.metrics.cvssMetricV31[SAFE_OFFSET(0)].cvssData.baseScore AS base_score,
        cve.metrics.cvssMetricV31[SAFE_OFFSET(0)].cvssData.baseSeverity AS severity,
        cve.published AS published_date,
        cve.lastModified AS last_modified,
        -- Generate a "rank" for every update, giving #1 to the most recent timestamp
        ROW_NUMBER() OVER(PARTITION BY cve.id ORDER BY cve.lastModified DESC) as row_num
    FROM {{ source('raw_layer', 'nvd_cves') }}
)

-- Only keep the latest version of every CVE
SELECT * EXCEPT(row_num)
FROM raw_data
WHERE row_num = 1
AND base_score IS NOT NULL
