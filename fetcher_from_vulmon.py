import requests
from bs4 import BeautifulSoup
import mysql.connector
from Get_Date import Get_Date


class CVEFetcher:
    def __init__(self, pages=11):
        self.base_url = "https://vulmon.com/searchpage?q=2025&sortby=bydate&page="
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'
        }
        self.pages = pages

        # تنظیمات اتصال به دیتابیس
        self.db_config = {
            'host': 'localhost',  # آدرس سرور دیتابیس
            'user': 'root',  # نام کاربری دیتابیس
            'password': 'toor',  # رمز عبور دیتابیس
            'database': 'cvedb'  # نام دیتابیس
        }

        # اتصال به دیتابیس
        self.db_connection = mysql.connector.connect(**self.db_config)
        self.cursor = self.db_connection.cursor()

    def find_keywords_in_description(self, description):
        keywords = ["buffer overflow", "sql injection", "xss", "rce", "dos", "csrf"]
        found = [kw for kw in keywords if kw.lower() in description.lower()]
        return found

    def fetch_cve_data(self):
        cve_list = []
        site = "Vulmon"
        for page in range(1, self.pages + 1):
            print(f"📄 Fetching page {page}...")
            try:
                response = requests.get(self.base_url + str(page), headers=self.headers, timeout=10)
                response.raise_for_status()
                soup = BeautifulSoup(response.content, 'html.parser')
                cve_items = soup.find_all('div', class_='item')

                for item in cve_items:
                    cve_id_tag = item.find('a', class_='header')
                    cve_id = cve_id_tag.text.strip() if cve_id_tag else 'N/A'

                    description_tag = item.find('div', class_='description')
                    description = description_tag.text.strip() if description_tag else 'N/A'

                    # دریافت تاریخ‌ها از فایل Get_Date
                    try:
                        published_date, updated_date, severity = Get_Date.get_cve_date(cve_id)
                    except:
                        published_date, updated_date, severity = "N/A", "N/A", "N/A"

                    # دریافت امتیاز CVSS
                    try:
                        cvss = item.find('div', class_='value').text.strip()
                    except:
                        cvss = "N/A"

                    cve_data = {
                        "cve_id": cve_id,
                        "description": description,
                        "cvss": cvss,
                        "published": published_date,
                        "updated": updated_date,
                        "severity": severity,
                        "site" : site
                    }

                    # اضافه کردن داده‌ها به لیست
                    cve_list.append(cve_data)

                    # ذخیره در دیتابیس
                    self.save_to_db(cve_data)

            except Exception as e:
                print(f"❌ خطا در صفحه {page}: {e}")

        return cve_list 

    def save_to_db(self, cve_data):
        # دستورات SQL برای ذخیره داده‌ها در جدول cves
        query = """
            INSERT INTO cves (cve_id, description, cvss_score, severity, published_date, lastModified_date, site)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            cve_data['cve_id'],
            cve_data['description'],
            cve_data['cvss'],
            cve_data['severity'],
            cve_data['published'],
            cve_data['updated'],
            cve_data['site']

        )

        try:
            self.cursor.execute(query, values)
            self.db_connection.commit()
            # print(f"✅ Data for {cve_data['cve_id']} inserted successfully.")
        except Exception as e:
            # print(f"❌ Error inserting data for {cve_data['cve_id']}: {e}")
            self.db_connection.rollback()

    def close_db(self):
        self.cursor.close()
        self.db_connection.close()