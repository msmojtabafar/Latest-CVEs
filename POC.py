import requests
import mysql.connector
from datetime import datetime, timedelta
from flask import Blueprint, render_template

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'toor',
    'database': 'cvedb'
}

poc_blueprint = Blueprint('poc', __name__)

def get_mysql_connection():
    return mysql.connector.connect(**DB_CONFIG)

def get_cves_with_poc(start_date, end_date):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "lastModStartDate": f"{start_date}T00:00:00.000Z",
        "lastModEndDate": f"{end_date}T23:59:59.000Z",
        "resultsPerPage": 2000
    }
    headers = {"User-Agent": "CVE PoC Collector"}

    response = requests.get(url, params=params, headers=headers)
    data = response.json()

    cves_with_poc = []

    for item in data.get("vulnerabilities", []):
        cve_id = item["cve"]["id"]
        references = item["cve"]["references"]
        poc_links = []

        for ref in references:
            url = ref.get("url", "").lower()
            if "poc" in url or "exploit" in url or "github" in url:
                poc_links.append(ref["url"])

        if poc_links:
            cves_with_poc.append({"cve_id": cve_id, "links": poc_links})

    return cves_with_poc

def save_pocs_to_db(cves_with_poc):
    conn = get_mysql_connection()
    cursor = conn.cursor()

    for item in cves_with_poc:
        cve_id = item["cve_id"]
        for link in item["links"]:
            cursor.execute("SELECT COUNT(*) FROM poc WHERE cve_id = %s AND poc_link = %s", (cve_id, link))
            if cursor.fetchone()[0] == 0:
                cursor.execute("INSERT INTO poc (cve_id, poc_link) VALUES (%s, %s)", (cve_id, link))

    conn.commit()
    cursor.close()
    conn.close()


@poc_blueprint.route('/view_pocs')
def view_pocs():
    today = datetime.utcnow()
    yesterday = today - timedelta(days=1)
    start_date = yesterday.strftime("%Y-%m-%d")
    end_date = today.strftime("%Y-%m-%d")

    cves = get_cves_with_poc(start_date, end_date)
    save_pocs_to_db(cves)

    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT cve_id, poc_link FROM poc ORDER BY id DESC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    grouped = {}
    for row in rows:
        cve_id = row["cve_id"]
        link = row["poc_link"]
        if cve_id not in grouped:
            grouped[cve_id] = []
        grouped[cve_id].append(link)

    grouped_cves = [{"cve_id": key, "links": val} for key, val in grouped.items()]

    return render_template('cve_with_poc.html', cves=grouped_cves)
