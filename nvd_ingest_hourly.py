import requests
import json
import time
import uuid
from datetime import datetime, timedelta
from google.cloud import secretmanager
from google.cloud import storage

# --- CONFIGURATION ---
PROJECT_ID = "cyberai-480816" 
BUCKET_NAME = f"{PROJECT_ID}-data-lake"
NVD_SECRET_ID = "nvd-api-key"

# DYNAMIC TIME WINDOW: Fetch only the last 70 minutes (10 min overlap safety)
NOW = datetime.utcnow()
START_DATE = (NOW - timedelta(minutes=70)).strftime("%Y-%m-%dT%H:%M:%S.000")
END_DATE = NOW.strftime("%Y-%m-%dT%H:%M:%S.000")

def get_secret(secret_id):
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")

def upload_to_gcs(data, filename):
    storage_client = storage.Client()
    bucket = storage_client.bucket(BUCKET_NAME)
    # Save to 'raw/nvd_hourly' to keep it separate from history
    blob = bucket.blob(f"raw/nvd_hourly/{filename}")
    blob.upload_from_string(json.dumps(data), content_type='application/json')
    print(f"Uploaded {filename} to GCS.")

def fetch_nvd_data():
    api_key = get_secret(NVD_SECRET_ID)
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": api_key}
    
    start_index = 0
    results_per_page = 2000
    
    print(f"Checking for NVD updates between {START_DATE} and {END_DATE}...")

    while True:
        # NOTICE: We use 'lastModStartDate' to find CHANGED vulnerabilities
        params = {
            "lastModStartDate": START_DATE,
            "lastModEndDate": END_DATE,
            "startIndex": start_index,
            "resultsPerPage": results_per_page
        }
        
        try:
            response = requests.get(base_url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                if not vulnerabilities:
                    print("No new updates found in the last hour.")
                    break
                
                # Generate unique filename using UUID so we don't overwrite
                batch_id = str(uuid.uuid4())[:8]
                batch_filename = f"nvd_update_{NOW.strftime('%H%M')}_{batch_id}.json"
                upload_to_gcs(vulnerabilities, batch_filename)
                
                total_results = data.get("totalResults", 0)
                print(f"Found {len(vulnerabilities)} updates. (Total pending: {total_results})")

                start_index += results_per_page
                if start_index >= total_results:
                    break
                time.sleep(0.6) 
            else:
                print(f"Error {response.status_code}: {response.text}")
                break
                
        except Exception as e:
            print(f"Exception: {str(e)}")
            break

if __name__ == "__main__":
    fetch_nvd_data()
