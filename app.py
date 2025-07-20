from flask import Flask, render_template, jsonify
from config import *
from model import db, CVE
from fetcher import fetch_cves

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
            'description': cve.description,
            'keywords': ', '.join(matched) if matched else '---'
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
    
    
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
