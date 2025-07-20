import requests
from datetime import datetime, timedelta
from model import CVE, db

def fetch_cves():
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "pubStartDate": (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z",
            "pubEndDate": datetime.utcnow().isoformat() + "Z",
            "startIndex": 0,
            "resultsPerPage": 10,
        }

        response = requests.get(url, params=params)
        if response.status_code != 200:
            raise Exception("Failed to fetch from NVD API")

        data = response.json()
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")
            desc = cve_data.get("descriptions", [{}])[0].get("value", "No description")
            severity = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
            score = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 0)
            published = datetime.strptime(cve_data.get("published", "2000-01-01T00:00Z")[:10], "%Y-%m-%d").date()

            # ذخیره در دیتابیس
            if not CVE.query.filter_by(cve_id=cve_id).first():
                db.session.add(CVE(
                    cve_id=cve_id,
                    description=desc,
                    severity=severity,
                    cvss_score=score,
                    published_date=published
                ))
        db.session.commit()
    except Exception as e:
        print("Error in fetch_cves:", e)
        raise Exception("Failed to fetch CVEs")
