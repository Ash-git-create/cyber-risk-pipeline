# 🛡️ Automated Cyber Risk Scoring Pipeline

> **A Serverless, End-to-End Data Engineering Pipeline on Google Cloud Platform**

   

## 📖 Project Overview

This project implements an automated pipeline that calculates **Real-Time Cyber Risk Scores** for internal infrastructure.

It ingests vulnerability data from three sources, normalizes it, and enriches it with threat intelligence to prioritize remediation. The pipeline is automated with **GitHub Actions** and **Google Cloud Build**, with **BigQuery** as the warehouse and **dbt** for transformations.

> **Status:** ran hourly from December 2025 to January 2026, 597 successful builds. The schedule is currently disabled, so the tables are not being refreshed.

### **The Problem**

Security teams are overwhelmed by thousands of vulnerabilities (CVEs). They cannot patch everything at once.

### **The Solution**

A data-driven scoring engine that prioritizes risks based on:

1.  **Severity:** Base CVSS Score (NVD).
2.  **Exploitability:** Is it being actively exploited in the wild? (CISA KEV).
3.  **Threat Chatter:** Are hackers discussing it right now? (AlienVault OTX).
4.  **Asset Criticality:** Is the vulnerable server important? (Internal Asset DB).

-----

## 🏗️ Architecture

1.  **Ingestion (ETL):** A Python script fetches data from NVD (API 2.0), CISA and OTX. It is submitted to a **Dataproc** cluster by `cloudbuild.yaml`, but the script itself is single-threaded `requests` code and does not use Spark. Cloud Run would be the cheaper host, see Known Limitations.
2.  **Storage (Data Lake):** Raw JSON data is stored in **Google Cloud Storage (GCS)**.
3.  **Loading (ELT):** **Cloud Build** triggers `bq load` to ingest data into **BigQuery** (Raw Layer).
4.  **Transformation:** **dbt** cleans, joins, and applies the Risk Scoring Formula to generate the `prioritized_risks` table.
5.  **Orchestration:** **GitHub Actions** triggers the pipeline hourly.

-----

## 🚀 Key Features

  * **Multi-Source Ingestion:**
      * **NVD (NIST):** Official CVE definitions and base scores.
      * **CISA KEV:** Federal list of Known Exploited Vulnerabilities.
      * **AlienVault OTX:** Real-time threat intelligence (Pulse Counts).
  * **Smart Enrichment:**
      * Uses "Metadata Injection" to link unstructured OTX threat pulses to specific CVE IDs.
      * *Demo Mode:* Injects historical high-profile CVEs (e.g., Log4j) to demonstrate risk scoring even during quiet periods.
  * **Custom Risk Logic:**
      * `Risk Score = (CVSS * Asset_Criticality) * (2.0 if Exploited) * (1.5 if Trending)`
  * **Infrastructure as Code:**
      * Pipeline defined in `cloudbuild.yaml`.
      * Scheduling defined in `.github/workflows/hourly.yml`.

-----

## 🛠️ Tech Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Orchestrator** | Google Cloud Build | Manages the step-by-step pipeline execution. |
| **Scheduler** | GitHub Actions | Triggers the build every hour (Cron). |
| **Job host** | Google Dataproc | Cluster the ingestion script is submitted to. The script is not a Spark job. |
| **Warehouse** | BigQuery | Stores raw JSON and final analytical tables. |
| **Transformation** | dbt (Data Build Tool) | Compiles SQL models and manages schema. |
| **Storage** | Cloud Storage (GCS) | Data Lake for raw JSON/NDJSON files. |
| **Language** | Python 3.9 | Custom ingestion scripts with `requests`. |

-----

## ⚙️ Setup & Deployment

### **1. Prerequisites**

  * Google Cloud Platform Account.
  * Enabled APIs: Cloud Build, Dataproc, BigQuery, Secret Manager.
  * Service Account with `Editor` permissions.

### **2. Environment Variables**

Store the following secrets in **Google Secret Manager**:

  * `nvd-api-key`: Your NIST API Key.
  * `otx-api-key`: Your AlienVault OTX API Key.

Store the following secret in **GitHub Actions Secrets**:

  * `GCP_SA_KEY`: Service Account JSON key for authentication.

### **3. Manual Execution (Testing)**

To trigger the full pipeline immediately from the terminal:

```bash
gcloud builds submit --config=cloudbuild.yaml .
```

### **4. Automated Execution**

The workflow is configured to run at **minute 0 of every hour** via GitHub Actions. It ran on that schedule from December 2025 to January 2026 for 597 successful builds, and is currently disabled.

  * Workflow File: `.github/workflows/hourly.yml`

Note that `nvd_ingest_hourly.py` currently requests a **7-day** window, not the 70-minute window the hourly cadence implies. Change `START_DATE` before re-enabling the schedule.

-----

## 📊 Data Models (dbt)

### **1. `stg_nvd` & `stg_otx`**

  * Cleans raw JSON data.
  * Deduplicates entries (keeping the latest `last_modified` timestamp).
  * Flattens nested JSON structures (e.g., NVD 2.0 `cve.metrics`).

### **2. `prioritized_risks.sql` (The Core Logic)**

Joins Assets, NVD, CISA, and OTX data to calculate the final score.

```sql
SELECT 
    hostname,
    cve_id,
    (base_score * criticality_score) 
      * (CASE WHEN is_exploited_cisa THEN 2.0 ELSE 1.0 END)
      * (CASE WHEN otx_pulse_count > 10 THEN 1.5 ELSE 1.0 END) 
    as final_risk_score
FROM joined_data
ORDER BY final_risk_score DESC
```

-----

## 📂 Repository Structure

```text
├── .github/workflows/   # GitHub Actions (cron scheduler)
│   └── hourly.yml
├── models/              # dbt SQL models
│   ├── prioritized_risks.sql
│   ├── stg_nvd.sql
│   ├── stg_otx.sql
│   ├── schema.yml       # Column tests and model docs
│   └── sources.yml      # BigQuery raw_layer sources
├── seeds/
│   └── assets.csv       # Example host inventory, 8 rows
├── nvd_ingest_hourly.py # Ingestion script (NVD, CISA, OTX)
├── cloudbuild.yaml      # Pipeline orchestration config
├── dbt_project.yml      # dbt configuration
├── profiles.yml         # BigQuery connection settings
└── README.md
```

-----

## ⚠️ Known Limitations

Worth reading before treating the output as a real risk ranking.

  * **Assets are cross-joined against every CVE.** `prioritized_risks.sql` has no product or version match, because the NVD ingest keeps only `cve_id`, `description`, `base_score` and `severity`, with no CPE data. Every CVE is therefore scored against every host, so the ranking reflects severity and asset criticality but not whether a host actually runs the affected software. Fixing this means ingesting the NVD `configurations` block and holding a per-host software inventory to match against.
  * **The ingestion script is not a Spark job.** It is submitted to Dataproc but runs single-threaded `requests` code. A Cloud Run job would do the same work for less.
  * **Demo mode injects known historical CVEs** such as Log4Shell so the scoring output is non-empty during quiet ingest windows. Those rows are not fresh findings.
  * **The `assets` table is a seed**, not a real inventory. `seeds/assets.csv` holds eight example hosts.
  * **The schedule is off.** Last successful run 9 January 2026.

## 🛡️ License

MIT. See [`LICENSE`](LICENSE). Data sources (NVD, CISA, OTX) are subject to their respective terms of use.
