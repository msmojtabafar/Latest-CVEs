import requests
import time
import logging
from datetime import datetime
from models import db, CVE

logging.basicConfig(
    filename="cve_fetch.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

API_KEY = ""  # اگر داری، بذار اینجا

def safe_request(url, headers, params, retries=5, delay=3):
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 429:
                wait_time = delay * (attempt + 1)
                logging.warning(f"Rate limit exceeded (429). Waiting {wait_time} seconds (attempt {attempt + 1})")
                time.sleep(wait_time)
                continue
            if response.status_code != 200:
                logging.error(f"HTTP error {response.status_code} on attempt {attempt + 1}")
                time.sleep(delay)
                continue
            return response
        except Exception as e:
            logging.exception(f"Request failed on attempt {attempt + 1}: {e}")
            time.sleep(delay)
    logging.critical("All retries failed.")
    return None

# def fetch_cves():
#     logging.info("Starting CVE fetch task...")
#     base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
#     headers = {"apiKey": API_KEY} if API_KEY else {}

#     page_size = 1000
#     start_index = 0

#     total_new = 0

#     while True:
#         params = {
#             "startIndex": start_index,
#             "resultsPerPage": page_size,
#             "pubStartDate": (datetime.utcnow().date().isoformat()) + "T00:00:00:000 UTC-00:00",
#         }

#         response = safe_request(base_url, headers, params)
#         if not response:
#             logging.error("Request failed. Stopping fetch task.")
#             break

#         data = response.json()
#         if "vulnerabilities" not in data or not data["vulnerabilities"]:
#             logging.info("No new CVEs found.")
#             break

#         new_count = 0
#         for item in data["vulnerabilities"]:
#             cve_data = item.get("cve", {})
#             cve_id = cve_data.get("id")
#             description = cve_data.get("descriptions", [{}])[0].get("value", "")
#             published = cve_data.get("published")
#             severity = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "")
#             score = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 0.0)

#             if not CVE.query.filter_by(cve_id=cve_id).first():
#                 cve_entry = CVE(
#                     cve_id=cve_id,
#                     description=description,
#                     severity=severity,
#                     cvss_score=score,
#                     published_date=datetime.fromisoformat(published[:-1])  # حذف Z
#                 )
#                 db.session.add(cve_entry)
#                 new_count += 1
#                 total_new += 1

#         db.session.commit()
#         logging.info(f"Page {start_index // page_size + 1} fetched successfully. New CVEs added: {new_count}")

#         if len(data["vulnerabilities"]) < page_size:
#             break

#         start_index += page_size
#         time.sleep(3)

#     logging.info(f"✅ CVE fetch task completed. Total new CVEs added: {total_new}")

def fetch_cves():
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'  # نمونه URL
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'apiKey': 'YOUR_API_KEY_HERE'  # اگر نیاز باشه
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        # پردازش داده‌ها
        for item in data.get("vulnerabilities", []):
            cve_id = item["cve"]["id"]
            # بررسی وجود
            if not CVE.query.filter_by(cve_id=cve_id).first():
                new_cve = CVE(
                    cve_id=cve_id,
                    description=item["cve"]["descriptions"][0]["value"],
                    severity=item.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", ""),
                    cvss_score=item.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 0),
                    published_date=datetime.fromisoformat(item["cve"]["published"])
                )
                db.session.add(new_cve)
        db.session.commit()
    elif response.status_code == 429:
        raise Exception("Rate limit exceeded (429)")
    else:
        raise Exception(f"Error fetching CVEs: {response.status_code}")