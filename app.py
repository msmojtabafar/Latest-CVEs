from flask import Flask, request, jsonify, render_template
from models import db, CVE
from cve_fetcher import fetch_cves 
import os
from apscheduler.schedulers.background import BackgroundScheduler
from cve_fetcher import fetch_cves


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:toor@localhost/cvedb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

def load_keywords():
    keyword_path = os.path.join(os.path.dirname(__file__), 'keywords.txt')
    if not os.path.exists(keyword_path):
        return []
    with open(keyword_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def extract_keywords(description, keyword_list):
    found = []
    desc_lower = (description or "").lower()
    for keyword in keyword_list:
        if keyword.lower() in desc_lower:
            found.append(keyword)
    return found

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/api/cves')
def get_cves():
    cves = CVE.query.order_by(CVE.published_date.desc()).all()
    keyword_list = load_keywords()

    return jsonify([
        {
            'id': c.cve_id,
            'desc': c.description,
            'severity': c.severity,
            'score': c.cvss_score,
            'date': c.published_date.isoformat(),
            'keywords': ', '.join(extract_keywords(c.description, keyword_list))
        }
        for c in cves
    ])

@app.route('/api/cve_search')
def search_cve():
    cve_id = request.args.get('cve_id')
    cve = CVE.query.filter_by(cve_id=cve_id).first()
    if not cve:
        return jsonify({"error": "CVE not found"}), 404

    keyword_list = load_keywords()
    keywords = extract_keywords(cve.description, keyword_list)

    return jsonify({
        'id': cve.cve_id,
        'desc': cve.description,
        'severity': cve.severity,
        'score': cve.cvss_score,
        'date': cve.published_date.isoformat(),
        'keywords': ', '.join(keywords)
    })

@app.route('/api/fetch_cves', methods=['GET'])
def fetch_cves_api():
    try:
        fetch_cves()
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500



scheduler = BackgroundScheduler()
scheduler.add_job(fetch_cves, 'interval', hours=3)
scheduler.start()


if __name__ == '__main__':
    app.run(debug=True)
