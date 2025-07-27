
# import requests

# class Get_Date:
#     def get_cve_date(cve_id):
#         url = f'https://cveawg.mitre.org/api/cve/{cve_id}'
#         try:
#             response = requests.get(url)
#             response.raise_for_status()
#             data = response.json()
            
#             Published_Date = data.get('cveMetadata', {}).get('datePublished', '🔴 No find Published date')
#             Published_Date = Published_Date[0:10]
#             Updated_Date = data.get('cveMetadata', {}).get('dateUpdated', '🔴 No find Updated date')
#             Updated_Date = Updated_Date[0:10]
#             severity = data.get("cvssV3", {}).get("baseSeverity", "N/A")
            

#         except requests.exceptions.RequestException as e:
#             Published_Date = "NA"
#             Updated_Date = "NA"
#             severity = "NA"
            
#         except ValueError:
#             print('خطا در تبدیل داده‌ها به JSON')
#             Published_Date = "NA"
#             Updated_Date = "NA"
#             severity = "NA"
            
#         return Published_Date , Updated_Date , severity


# import requests

# class Get_Date:
#     @staticmethod
#     def get_cve_date(cve_id):
#         url = f'https://cveawg.mitre.org/api/cve/{cve_id}'
#         try:
#             response = requests.get(url, timeout=10)
#             response.raise_for_status()
#             data = response.json()

#             published_date = data.get('cveMetadata', {}).get('datePublished', '🔴 No find Published date')[:10]
#             updated_date = data.get('cveMetadata', {}).get('dateUpdated', '🔴 No find Updated date')[:10]

#             # استخراج severity (از scoring V3 یا V2 اگر V3 نبود)
#             severity = (
#                 data.get('containers', {}).get('cna', {}).get('metrics', [{}])[0]
#                 .get('cvssV3', {})
#                 .get('baseSeverity', 'N/A')
#             )

#         except requests.exceptions.RequestException as e:
#             published_date = "N/A"
#             updated_date = "N/A"
#             severity = "N/A"
#         except ValueError:
#             print('⚠️ خطا در تبدیل داده‌ها به JSON')
#             published_date = "N/A"
#             updated_date = "N/A"
#             severity = "N/A"

#         return published_date, updated_date, severity





import requests

class Get_Date:
    @staticmethod
    def get_cve_date(cve_id):
        url = f'https://cveawg.mitre.org/api/cve/{cve_id}'
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            published_date = data.get('cveMetadata', {}).get('datePublished', 'N/A')[:10]
            updated_date = data.get('cveMetadata', {}).get('dateUpdated', 'N/A')[:10]

          
            severity = "N/A"
            metrics = data.get("containers", {}).get("cna", {}).get("metrics", [])
            # print(metrics)
            for m in metrics:
                if "cvssV3_1" in m:
                    severity = m["cvssV3_1"].get("baseSeverity", "N/A")
                    break

                elif "cvssV4_0" in m:
                    severity = m["cvssV4_0"].get("baseSeverity", "N/A")
                    break

        except requests.exceptions.RequestException:
            published_date = "N/A"
            updated_date = "N/A"
            severity = "N/A"
        except ValueError:
            # print('⚠️ خطا در تبدیل JSON')
            published_date = "N/A"
            updated_date = "N/A"
            severity = "N/A"

        return published_date, updated_date, severity