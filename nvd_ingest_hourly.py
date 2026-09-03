import requests
import json
import time
import uuid
import os
from datetime import datetime, timedelta
from google.cloud import secretmanager
from google.cloud import storage

# --- CONFIGURATION ---
PROJECT_ID = os.getenv("GCP_PROJECT_ID", "cyberai-480816")
BUCKET_NAME = f"{PROJECT_ID}-data-lake"

# Secrets
NVD_SECRET_ID = "nvd-api-key"
OTX_SECRET_ID = "otx-api-key"

# URLs
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/cve"

# Ingest window. Set INGEST_WINDOW_MINUTES=70 to match the hourly schedule
# (60 minutes plus 10 minutes of overlap). Defaults to 7 days, which is what
# the last runs used, so a single manual run returns a useful backfill.
NOW = datetime.utcnow()
WINDOW_MINUTES = int(os.getenv("INGEST_WINDOW_MINUTES", 7 * 24 * 60))
START_DATE = (NOW - timedelta(minutes=WINDOW_MINUTES)).strftime("%Y-%m-%dT%H:%M:%S.000")
END_DATE = NOW.strftime("%Y-%m-%dT%H:%M:%S.000")

def get_secret(secret_id):
    """Fetches API keys from Google Secret Manager"""
    try:
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8").strip()
    except Exception as e:
        print(f"WARNING: Could not fetch secret {secret_id}: {e}")
        return None

def upload_to_gcs(data, filename, folder):
    """Uploads JSON data to a specific folder in GCS"""
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(f"raw/{folder}/{filename}")
        blob.upload_from_string(json.dumps(data), content_type='application/json')
        print(f"Uploaded {filename} to gs://{BUCKET_NAME}/raw/{folder}/")
    except Exception as e:
        print(f"ERROR: Failed to upload {filename}: {e}")

def fetch_nvd_data():
    """Fetches NVD updates for the last hour"""
    api_key = get_secret(NVD_SECRET_ID)
    if not api_key:
        print("Skipping NVD: No API Key found.")
        return []

    headers = {"apiKey": api_key}
    start_index = 0
    results_per_page = 2000
    all_cves = []

    print(f"--- 1. NVD: Checking updates between {START_DATE} and {END_DATE} ---")

    while True:
        params = {
            "lastModStartDate": START_DATE,
            "lastModEndDate": END_DATE,
            "startIndex": start_index,
            "resultsPerPage": results_per_page
        }
        
        try:
            response = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                if not vulnerabilities:
                    print("No new NVD updates found.")
                    break
                
                # Collect CVEs for OTX lookup later
                all_cves.extend(vulnerabilities)

                # Upload Batch
                batch_id = str(uuid.uuid4())[:8]
                batch_filename = f"nvd_update_{NOW.strftime('%H%M')}_{batch_id}.json"
                upload_to_gcs(vulnerabilities, batch_filename, "nvd_hourly")
                
                total_results = data.get("totalResults", 0)
                print(f"Fetched {len(vulnerabilities)} CVEs. (Total pending: {total_results})")

                start_index += results_per_page
                if start_index >= total_results:
                    break
                time.sleep(0.6) # NVD Rate limit safety
            else:
                print(f"NVD Error {response.status_code}: {response.text}")
                break
                
        except Exception as e:
            print(f"NVD Exception: {str(e)}")
            break
            
    return all_cves

def fetch_cisa_data():
    """Fetches the full CISA Known Exploited Vulnerabilities catalog"""
    print(f"--- 2. CISA: Fetching KEV Catalog ---")
    try:
        # CISA is a public URL, no key needed
        response = requests.get(CISA_URL, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            filename = f"cisa_kev_{NOW.strftime('%Y%m%d%H')}.json"
            upload_to_gcs(vulnerabilities, filename, "cisa")
            print(f"Successfully uploaded {len(vulnerabilities)} CISA KEVs.")
        else:
            print(f"CISA Error {response.status_code}")

    except Exception as e:
        print(f"CISA Exception: {str(e)}")

def fetch_otx_data(nvd_updates):
    """
    Queries OTX for the specific CVEs found in the NVD step.
    Uses Rate Limiting to respect API limits.
    """
    print(f"--- 3. OTX: Enriching {len(nvd_updates)} CVEs ---")
    
    api_key = get_secret(OTX_SECRET_ID)
    if not api_key:
        print("Skipping OTX: No API Key found.")
        return

    headers = {"X-OTX-API-KEY": api_key}
    otx_results = []

    # Loop through the CVEs we just found in NVD
    for i, item in enumerate(nvd_updates):
        try:
            cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
            if not cve_id:
                continue

            url = f"{OTX_BASE_URL}/{cve_id}/general"
            response = requests.get(url, headers=headers, timeout=10) #

            if response.status_code == 200:
                data = response.json()
                # We only really care about the 'pulse_info' (threat count)
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                otx_results.append({
                    "cve_id": cve_id,
                    "pulse_count": pulse_count,
                    "fetched_at": datetime.utcnow().isoformat()
                })
                print(f"[{i+1}/{len(nvd_updates)}] Found OTX data for {cve_id}: {pulse_count} pulses")

            elif response.status_code == 404:
                # 404 is common; it just means OTX has no data for this CVE yet.
                print(f"[{i+1}/{len(nvd_updates)}] No OTX data for {cve_id}")
            
            elif response.status_code == 429:
                print("OTX Rate Limit Hit! Sleeping for 5 seconds...")
                time.sleep(5)
            
            else:
                print(f"OTX Error {response.status_code} for {cve_id}")

            # RATE LIMITING: Sleep 0.5s between requests
            time.sleep(0.5)

        except Exception as e:
            print(f"Error processing {cve_id}: {e}")

    if otx_results:
        filename = f"otx_enrichment_{NOW.strftime('%Y%m%d%H')}.json"
        upload_to_gcs(otx_results, filename, "otx")

if __name__ == "__main__":
    # 1. Fetch NVD (The real-time updates)
    nvd_cves = fetch_nvd_data()
    
    # --- DEMO TRICK: INJECT FAMOUS CVEs ---
    # We add these to ensure OTX has something to find, 
    # even if recent NVD updates are boring.
    print("--- DEMO MODE: Injecting Famous CVEs for OTX Lookup ---")
    famous_cves = [
        {"cve": {"CVE_data_meta": {"ID": "CVE-2021-44228"}}}, # Log4J (Huge OTX data)
        {"cve": {"CVE_data_meta": {"ID": "CVE-2017-0144"}}},  # EternalBlue
        {"cve": {"CVE_data_meta": {"ID": "CVE-2019-0708"}}},  # BlueKeep
        {"cve": {"CVE_data_meta": {"ID": "CVE-2023-4863"}}}   # Recent Libwebp
    ]
    
    # Combine Real NVD hits + Famous CVEs
    # (We use a simple list merge here)
    combined_cves = nvd_cves + famous_cves
    # -------------------------------------

    # 2. Fetch CISA (Always fetch full list)
    fetch_cisa_data()

    # 3. Fetch OTX (Now querying the combined list)
    if combined_cves:
        fetch_otx_data(combined_cves)
    else:
        print("No NVD updates and no manual injection. Skipping OTX.")