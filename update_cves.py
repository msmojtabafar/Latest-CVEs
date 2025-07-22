import requests
import mysql.connector
from datetime import datetime, timedelta

def get_cves_from_nvd(start_date, end_date):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "lastModStartDate": f"{start_date}T00:00:00.000Z",
        "lastModEndDate": f"{end_date}T23:59:59.000Z",
    }
    headers = {"User-Agent": "my-cve-fetcher"}
    response = requests.get(url, params=params, headers=headers)
    response.raise_for_status()
    data = response.json()

    cve_dict = {}
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id")
        last_modified = cve_data.get("lastModified")

        if cve_id and last_modified:
            cve_dict[cve_id] = last_modified

    return cve_dict

def update_modified_dates(cve_dict):
    conn = mysql.connector.connect(
        host="localhost",
        user="root", 
        password="toor",  
        database="cvedb"
    )
    cur = conn.cursor()

    updated_count = 0
    for cve_id, new_date in cve_dict.items():
        cur.execute("SELECT lastModified_date FROM cves WHERE cve_id = %s", (cve_id,))
        result = cur.fetchone()

        if result:
            old_date = result[0]
            if old_date != new_date:
                cur.execute(
                    "UPDATE cves SET lastModified_date = %s WHERE cve_id = %s",
                    (new_date, cve_id)
                )
                updated_count += 1

    conn.commit()
    conn.close()
    return updated_count

def run_update_for_recent_days():
    today = datetime.utcnow().date()
    yesterday = today - timedelta(days=1)
    start_date = str(yesterday)
    end_date = str(today)

    cve_dict = get_cves_from_nvd(start_date, end_date)
    updated = update_modified_dates(cve_dict)
    return len(cve_dict), updated  
