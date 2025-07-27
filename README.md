CVE Fetcher Tool
Welcome to the CVE Fetcher Tool! 🚀

This powerful tool automatically fetches the latest CVEs (Common Vulnerabilities and Exposures) from both the National Vulnerability Database (NVD) and Vulmon, and securely stores them in a database. No more worrying about missing critical vulnerabilities from your favorite sources!

🔑 Key Features:
* Multi-Source Collection: Retrieves CVE data from both NVD (cve.org) and Vulmon to ensure comprehensive coverage of the latest vulnerabilities.

* Automatic Updates: The tool regularly checks for new CVEs from both sources, keeping your database consistently up-to-date.

* HTML Dashboard: A clean and user-friendly HTML interface powered by Flask displays all collected CVEs in one place.

* Search & Filter: Quickly search and filter vulnerabilities by keyword, severity, or publication date.

* Manual Fetching: Want instant updates? Just click the Fetch button to manually retrieve the most recent CVEs from both platforms.

* PoC Detection: Scans for Proof-of-Concept (PoC) links for recently updated CVEs and stores them in a separate table for quick access.

* PoC Dashboard: A dedicated page displays PoC-enabled CVEs in a categorized and organized layout — ideal for quickly spotting exploitable vulnerabilities.

🚀 How to Use:
* Install dependencies: Follow the installation guide to set up the Python and Flask environment.

* Run the tool: Start the Flask server and open the dashboard in your browser.

* Fetch manually: Use the Fetch button to update your CVE database with fresh entries from NVD and Vulmon.

* Explore PoCs: Navigate to the PoC dashboard to see which CVEs have working proof-of-concept exploits available in the last 24 hours.

This tool is ideal for security researchers, SOC analysts, and vulnerability management teams who want a real-time, comprehensive, and centralized view of the latest cybersecurity threats from trusted databases.

