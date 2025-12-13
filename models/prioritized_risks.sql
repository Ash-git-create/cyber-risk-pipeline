WITH 
-- 1. Get our internal assets
assets AS (
    SELECT hostname, ip_address, os, criticality_score 
    FROM {{ source('raw_layer', 'assets') }}
),

-- 2. Get cleaned vulnerabilities (NVD)
nvd AS (
    SELECT * FROM {{ ref('stg_nvd') }}
),

-- 3. Get CISA Known Exploited (Just get the IDs)
cisa AS (
    SELECT DISTINCT cveID 
    FROM {{ source('raw_layer', 'cisa_kev') }}
),

-- 4. Get OTX Threat Intel
otx AS (
    SELECT * FROM {{ ref('stg_otx') }}
),

-- 5. Match Assets to Vulnerabilities & Enrich with Intel
vuln_matches AS (
    SELECT 
        a.hostname,
        a.criticality_score,
        n.cve_id,
        n.base_score,
        n.severity,
        n.description,
        
        -- CISA Flag: Is it being exploited?
        CASE WHEN c.cveID IS NOT NULL THEN TRUE ELSE FALSE END AS is_exploited_cisa,
        
        -- OTX Data: How many pulses? (Default to 0 if null)
        COALESCE(o.pulse_count, 0) as otx_pulse_count

    FROM assets a
    CROSS JOIN nvd n
    LEFT JOIN cisa c ON n.cve_id = c.cveID
    LEFT JOIN otx o  ON n.cve_id = o.cve_id
)

-- 6. Calculate Final Risk Score
SELECT 
    *,
    -- THE RISK FORMULA:
    -- Base Risk = (CVSS Score * Asset Criticality)
    -- Multiplier 1 (CISA): If Exploited, multiply by 2.0. If not, 1.0.
    -- Multiplier 2 (OTX): If Trending (>10 pulses), multiply by 1.5. If not, 1.0.
    (
        (base_score * criticality_score) 
        * (CASE WHEN is_exploited_cisa THEN 2.0 ELSE 1.0 END)
        * (CASE WHEN otx_pulse_count > 10 THEN 1.5 ELSE 1.0 END)
    ) as final_risk_score,

    -- Generate a Human-Readable Action Plan
    CASE 
        WHEN is_exploited_cisa THEN 'CRITICAL: Patch Immediately (Active Exploit)'
        WHEN otx_pulse_count > 10 THEN 'HIGH: Patch Next (Trending Threat)'
        ELSE 'Routine Patching'
    END as action_plan

FROM vuln_matches
ORDER BY final_risk_score DESC