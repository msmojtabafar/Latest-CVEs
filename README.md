CVE Fetcher Tool
Welcome to the CVE Fetcher Tool! 🚀

This powerful tool automatically fetches the latest CVEs (Common Vulnerabilities and Exposures) from the National Vulnerability Database (NVD) and stores them securely in a database. No more worrying about missing critical vulnerabilities!

🔑 Key Features:
Automatic Updates: The tool checks for new CVEs regularly, ensuring your database is always up-to-date.

HTML Dashboard: A clean and user-friendly HTML page powered by Flask to display all the saved CVEs.

Search & Filter: Easily search for specific vulnerabilities and apply filters to narrow down your results.

Manual Fetching: Need fresh data right away? Just click the Fetch button to manually retrieve the latest CVEs at any time.

PoC Detection: The tool fetches proof-of-concept (PoC) links for CVEs that were updated in the past 24 hours, and stores them in a separate table.

PoC Dashboard: A dedicated HTML page displays CVEs with available PoC links in a grouped and organized format — perfect for quickly identifying exploitable vulnerabilities.

🚀 How to Use:
Install dependencies: Follow the installation guide to set up the environment.

Run the tool: Start the Flask server to access the dashboard and explore the CVEs.

Fetch manually: Click on the "Fetch" button to update the data whenever you need.

View PoCs: Navigate to the PoC dashboard to view CVEs with PoC links discovered in the last 24 hours.

This tool is perfect for security researchers, SOC teams, and vulnerability analysts who want to stay on top of the latest security threats in real-time.


