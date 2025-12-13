WITH 
-- 1. Get our internal assets
assets AS (
    SELECT hostname, ip_address, os, criticality_score 
    FROM {{ source('raw_layer', 'assets') }}
),

-- 2. Get cleaned vulnerabilities
nvd AS (
    SELECT * FROM {{ ref('stg_nvd') }}
),

-- 3. Get CISA Known Exploited (Just get the IDs)
cisa AS (
    SELECT DISTINCT cveID FROM {{ source('raw_layer', 'cisa_kev') }}
),

-- 4. Match Assets to Vulnerabilities
-- (Using CROSS JOIN for this demo since we don't have real software versions installed)
vuln_matches AS (
    SELECT 
        a.hostname,
        a.criticality_score,
        n.cve_id,
        n.base_score,
        n.severity,
        n.description,
        CASE WHEN c.cveID IS NOT NULL THEN 1 ELSE 0 END AS is_exploited_cisa
    FROM assets a
    CROSS JOIN nvd n
    LEFT JOIN cisa c ON n.cve_id = c.cveID
)

-- 5. Calculate Final Risk Score
SELECT 
    *,
    -- FORMULA: (Base Score * Asset Criticality) + (20 points if Exploited)
    (base_score * criticality_score) + (CASE WHEN is_exploited_cisa = 1 THEN 20 ELSE 0 END) as final_risk_score
FROM vuln_matches
ORDER BY final_risk_score DESC
