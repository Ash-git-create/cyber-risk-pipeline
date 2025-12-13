WITH raw_otx AS (
    SELECT 
        cve_id,
        pulse_count,
        fetched_at,
        -- Deduplicate: Keep the most recent fetch for each CVE
        ROW_NUMBER() OVER(PARTITION BY cve_id ORDER BY fetched_at DESC) as row_num
    FROM {{ source('raw_layer', 'otx_intel') }}
)

SELECT 
    cve_id,
    pulse_count,
    fetched_at
FROM raw_otx
WHERE row_num = 1