from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class CVE(db.Model):
    __tablename__ = 'cves'

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    cvss_score = db.Column(db.Float, nullable=False)
    published_date = db.Column(db.Date, default=datetime.utcnow)
    lastModified_date = db.Column(db.Date, default=datetime.utcnow)
    site = db.Column(db.String(10))
