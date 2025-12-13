# 🛡️ Automated Cyber Risk Scoring Pipeline

> **A Serverless, End-to-End Data Engineering Pipeline on Google Cloud Platform**

   

## 📖 Project Overview

This project implements an automated pipeline that calculates **Real-Time Cyber Risk Scores** for internal infrastructure.

It ingests vulnerability data from three distinct sources, normalizes it, and enriches it with threat intelligence to prioritize remediation efforts. The pipeline is fully automated using **GitHub Actions** and **Google Cloud Build**, processing data via **Dataproc (Spark)** and **BigQuery**, with transformations managed by **dbt**.

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

1.  **Ingestion (ETL):** A Python script running on **Dataproc** fetches data from NVD (API 2.0), CISA, and OTX.
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
      * Scheduling defined in `.github/workflows/hourly_run.yml`.

-----

## 🛠️ Tech Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Orchestrator** | Google Cloud Build | Manages the step-by-step pipeline execution. |
| **Scheduler** | GitHub Actions | Triggers the build every hour (Cron). |
| **Processing** | Google Dataproc | Serverless Spark cluster for API fetching. |
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

The pipeline is configured to run automatically at **minute 0 of every hour** via GitHub Actions.

  * Workflow File: `.github/workflows/hourly_run.yml`

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
├── .github/workflows/   # GitHub Actions (Cron Scheduler)
├── models/              # dbt SQL Models
│   ├── prioritized_risks.sql
│   ├── stg_nvd.sql
│   └── stg_otx.sql
├── nvd_ingest_hourly.py # Main Python Ingestion Script
├── cloudbuild.yaml      # Pipeline Orchestration Config
├── dbt_project.yml      # dbt Configuration
├── profiles.yml         # BigQuery Connection Settings
└── README.md            # Documentation
```

-----

## 🛡️ License

This project is for educational and portfolio purposes. Data sources (NVD, CISA, OTX) are subject to their respective terms of use.
