from flask import Flask, render_template, jsonify
from config import *
from model import db, CVE
from fetcher import fetch_cves
from flask import request, redirect, url_for
from update_cves import run_update_for_recent_days
from POC import poc_blueprint
from fetcher_from_vulmon import CVEFetcher 

app = Flask(__name__)
app.config.from_pyfile("config.py")
db.init_app(app)


def load_keywords():
    try:
        with open('keywords.txt', 'r', encoding='utf-8') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        return []

@app.route("/")

def show_cves():
    cves = CVE.query.order_by(CVE.published_date.desc()).all()
    keywords = load_keywords()
    
    matched_cves = []
    for cve in cves:
        description = cve.description.lower() if cve.description else ""
        matched = [kw for kw in keywords if kw in description]

        matched_cves.append({
            'cve_id': cve.cve_id,
            'severity': cve.severity,
            'cvss_score': cve.cvss_score,
            'published_date': cve.published_date,
            'lastModified_date': cve.lastModified_date,
            'description': cve.description,
            'keywords': ', '.join(matched) if matched else '---',
            'site': cve.site

        })

    return render_template('index.html', cves=matched_cves, total=len(cves))


@app.route("/fetch", methods=["POST"])
def fetch():
    try:
        fetch_cves()
        return jsonify({"message": "Fetched successfully!"})
    except Exception as e:
        print("Error in /fetch:", e)
        return jsonify({"error": str(e)}), 500


@app.route('/get_description/<cve_id>')
def get_description(cve_id):
    cve = db.session.query(CVE).filter_by(cve_id=cve_id).first()
    if cve:
        return jsonify({'description': cve.description})
    else:
        return jsonify({'error': 'CVE not found'}), 404




@app.route("/update-cve-dates", methods=["POST"])
def update_cve_dates():
    try:
        run_update_for_recent_days()
    except Exception as e:
        print(f"خطا در بروزرسانی CVEها: {str(e)}")
    return '', 204  # No Content 


@app.route("/update")
def show_update_table():
    cves = CVE.query.order_by(CVE.lastModified_date.desc()).all()
    return render_template("update.html", cves=cves)


app.register_blueprint(poc_blueprint, url_prefix='/poc')



@app.route("/fetch-from-vulmon")
def fetch_vulmon():

    try:
        fetcher = CVEFetcher(pages=11)
        data = fetcher.fetch_cve_data()
        fetcher.close_db()
        return jsonify({"message": "Fetched successfully!"})
    except Exception as e:
        print("Error in /fetch from vulmon:", e)
        return jsonify({"error": str(e)}), 500



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)