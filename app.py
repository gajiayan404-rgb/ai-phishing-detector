import os
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
os.makedirs("instance", exist_ok=True)
print("DB Absolute Path in use:", os.path.abspath("instance/scan_records.db"))
print("Instance folder exists:", os.path.isdir("instance"))
print("File exists:", os.path.isfile("instance/scan_records.db"))
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, make_response, session
from flask_cors import CORS
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import re
import imaplib
import email
from email.header import decode_header
import threading
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import validators
from flask_sqlalchemy import SQLAlchemy

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'phishshield-default-secret-key-xyz')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///scan_records.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
CORS(app)
db = SQLAlchemy(app)

class ScanRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(255))
    subject = db.Column(db.String(500))
    scanned_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    is_phishing = db.Column(db.Boolean, default=False)
    threat_score = db.Column(db.Float)
    recommendations = db.Column(db.Text)
    deleted = db.Column(db.Boolean, default=False)
    def to_dict(self):
        rec_list = [r.strip() for r in (self.recommendations or "").split("\n") if r.strip()]
        score = round(float(self.threat_score or 0.0), 1)
        if score >= 75:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 25:
            level = "MEDIUM"
        else:
            level = "LOW"
        return {
            "id": self.id,
            "sender": self.sender or "Unknown Sender",
            "subject": self.subject or "(No Subject)",
            "scanned_at": self.scanned_at.strftime('%Y-%m-%d %H:%M:%S') if self.scanned_at else "",
            "is_phishing": bool(self.is_phishing),
            "threat_score": score,
            "threat_level": level,
            "recommendations": self.recommendations or "",
            "recommendations_list": rec_list
        }

    def __repr__(self):
        return f"<ScanRecord {self.subject}>"

with app.app_context():
    db.create_all()

MODEL_NAME = "ealvaradob/bert-finetuned-phishing"
print("Loading BERT model... (first time takes ~1 minute)")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
model.eval()
print("[OK] Model loaded!")

def extract_urls(text):
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text)

def analyze_email_text(email_text):
    inputs = tokenizer(
        email_text,
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding=True
    )
    with torch.no_grad():
        outputs = model(**inputs)
        probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
    phishing_prob = probabilities[0][1].item()
    return {
        "phishing_probability": round(phishing_prob * 100, 2),
        "is_phishing": phishing_prob > 0.5,
        "confidence": round(max(probabilities[0].tolist()) * 100, 2)
    }

def extract_suspicious_keywords(text):
    keywords = [
        'urgent', 'verify', 'suspend', 'limited time', 'act now',
        'confirm account', 'unusual activity', 'click here',
        'password', 'bank account', 'credit card',
        'winner', 'congratulations', 'claim', 'prize',
        'inheritance', 'wire transfer'
    ]
    found = []
    text_lower = text.lower()
    for kw in keywords:
        if kw in text_lower:
            found.append(kw)
    return found

def analyze_url(url):
    result = {"url": url, "is_malicious": False, "risk_score": 0, "issues": []}
    if not validators.url(url):
        result["issues"].append("Invalid URL format")
        result["risk_score"] = 30
        return result
    url_lower = url.lower()
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        result["issues"].append("Uses IP address")
        result["risk_score"] += 30
    suspicious = ['verify', 'account', 'secure', 'login', 'update', 'password']
    if any(s in url_lower for s in suspicious):
        result["issues"].append("Suspicious keywords")
        result["risk_score"] += 20
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly']
    if any(s in url_lower for s in shorteners):
        result["issues"].append("URL shortener detected")
        result["risk_score"] += 15
    if '@' in url:
        result["issues"].append("Contains @ symbol")
        result["risk_score"] += 40
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
    if any(url_lower.endswith(tld) for tld in suspicious_tlds):
        result["issues"].append("Suspicious TLD")
        result["risk_score"] += 25
    result["is_malicious"] = result["risk_score"] >= 50
    result["risk_score"] = min(100, result["risk_score"])
    return result

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "message": "Phishing Detector ready"})

def process_email_analysis(subject, sender, email_text):
    full_text = f"{subject} {email_text}".strip()
    text_analysis = analyze_email_text(full_text)
    urls = extract_urls(email_text)
    url_analysis = [analyze_url(url) for url in urls[:5]]
    keywords = extract_suspicious_keywords(full_text)
    threat_score = text_analysis['phishing_probability']
    if url_analysis:
        malicious_count = sum(1 for u in url_analysis if u['is_malicious'])
        threat_score = min(100, threat_score + (malicious_count * 20))
    if len(keywords) > 3:
        threat_score = min(100, threat_score + 10)
    if threat_score >= 75:
        threat_level, color = "CRITICAL", "red"
    elif threat_score >= 50:
        threat_level, color = "HIGH", "orange"
    elif threat_score >= 25:
        threat_level, color = "MEDIUM", "yellow"
    else:
        threat_level, color = "LOW", "green"
    recommendations = []
    if threat_level in ["CRITICAL", "HIGH"]:
        recommendations = [
            "⚠️ DO NOT click any links",
            "⚠️ DO NOT provide personal info",
            "🗑️ Delete immediately",
            "📧 Report as phishing"
        ]
    elif threat_level == "MEDIUM":
        recommendations = [
            "⚡ Exercise caution",
            "🔍 Verify sender carefully"
        ]
    else:
        recommendations = ["✅ Email appears legitimate"]
    if keywords:
        recommendations.append(f"⚠️ Found {len(keywords)} suspicious keyword(s)")
    return {
        "threat_score": round(threat_score, 2),
        "threat_level": threat_level,
        "color": color,
        "is_phishing": threat_score >= 50,
        "recommendations": recommendations,
        "analysis": {
            "text_analysis": text_analysis,
            "urls_found": len(urls),
            "url_analysis": url_analysis,
            "suspicious_keywords": keywords,
            "sender": sender
        }
    }

@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        if not data or 'email_text' not in data:
            return jsonify({"error": "email_text required"}), 400
        email_text = data['email_text']
        subject = data.get('subject', '')
        sender = data.get('sender', '')
        result = process_email_analysis(subject, sender, email_text)
        scan = ScanRecord(
            sender=sender,
            subject=subject,
            is_phishing=result["is_phishing"],
            threat_score=result["threat_score"],
            recommendations="\n".join(result["recommendations"])
        )
        db.session.add(scan)
        db.session.commit()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/')
def home():
    return redirect(url_for('scan_history'))

@app.route('/scan-history')
def scan_history():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str).strip()
    filter_phish = request.args.get('filter_phish', 'all', type=str)
    since = request.args.get('since', '', type=str)
    
    query = ScanRecord.query.filter_by(deleted=False)
    if search:
        search_pattern = f'%{search}%'
        query = query.filter(
            (ScanRecord.sender.ilike(search_pattern)) | 
            (ScanRecord.subject.ilike(search_pattern)) |
            (ScanRecord.recommendations.ilike(search_pattern))
        )
    if filter_phish == 'phishing':
        query = query.filter((ScanRecord.is_phishing == True) | (ScanRecord.threat_score >= 50))
    elif filter_phish == 'safe':
        query = query.filter((ScanRecord.is_phishing == False) & (ScanRecord.threat_score < 50))
    elif filter_phish == 'critical':
        query = query.filter(ScanRecord.threat_score >= 75)
    elif filter_phish == 'suspicious':
        query = query.filter((ScanRecord.threat_score >= 50) & (ScanRecord.threat_score < 75))

    if since:
        now = datetime.utcnow()
        if since == '1hr':
            query = query.filter(ScanRecord.scanned_at >= now - timedelta(hours=1))
        elif since == '24hr':
            query = query.filter(ScanRecord.scanned_at >= now - timedelta(hours=24))
        elif since == '7day':
            query = query.filter(ScanRecord.scanned_at >= now - timedelta(days=7))

    records = query.order_by(ScanRecord.scanned_at.desc(), ScanRecord.id.desc()).paginate(page=page, per_page=12, error_out=False)
    deleted_id = session.pop('deleted_id', None)
    
    total_scans = ScanRecord.query.filter_by(deleted=False).count()
    phishing_count = ScanRecord.query.filter_by(deleted=False).filter((ScanRecord.is_phishing == True) | (ScanRecord.threat_score >= 50)).count()
    safe_count = max(0, total_scans - phishing_count)
    latest_threat = ScanRecord.query.filter_by(deleted=False).filter((ScanRecord.is_phishing == True) | (ScanRecord.threat_score >= 50)).order_by(ScanRecord.id.desc()).first()
    latest_record = ScanRecord.query.filter_by(deleted=False).order_by(ScanRecord.id.desc()).first()
    latest_id = latest_record.id if latest_record else 0

    return render_template(
        'index.html',
        records=records,
        search=search,
        filter_phish=filter_phish,
        since=since,
        deleted_id=deleted_id,
        total_scans=total_scans,
        phishing_count=phishing_count,
        safe_count=safe_count,
        latest_threat=latest_threat,
        latest_id=latest_id
    )

@app.route('/api/records-live')
def records_live_api():
    last_id = request.args.get('last_id', 0, type=int)
    limit = min(request.args.get('limit', 15, type=int), 100)
    search = request.args.get('search', '', type=str).strip()
    filter_phish = request.args.get('filter_phish', 'all', type=str)
    since = request.args.get('since', '', type=str)

    query = ScanRecord.query.filter_by(deleted=False)
    if search:
        search_pattern = f'%{search}%'
        query = query.filter(
            (ScanRecord.sender.ilike(search_pattern)) | 
            (ScanRecord.subject.ilike(search_pattern)) |
            (ScanRecord.recommendations.ilike(search_pattern))
        )
    if filter_phish == 'phishing':
        query = query.filter((ScanRecord.is_phishing == True) | (ScanRecord.threat_score >= 50))
    elif filter_phish == 'safe':
        query = query.filter((ScanRecord.is_phishing == False) & (ScanRecord.threat_score < 50))
    elif filter_phish == 'critical':
        query = query.filter(ScanRecord.threat_score >= 75)
    elif filter_phish == 'suspicious':
        query = query.filter((ScanRecord.threat_score >= 50) & (ScanRecord.threat_score < 75))

    if since:
        now = datetime.utcnow()
        if since == '1hr':
            query = query.filter(ScanRecord.scanned_at >= now - timedelta(hours=1))
        elif since == '24hr':
            query = query.filter(ScanRecord.scanned_at >= now - timedelta(hours=24))
        elif since == '7day':
            query = query.filter(ScanRecord.scanned_at >= now - timedelta(days=7))

    total_scans = ScanRecord.query.filter_by(deleted=False).count()
    phishing_count = ScanRecord.query.filter_by(deleted=False).filter((ScanRecord.is_phishing == True) | (ScanRecord.threat_score >= 50)).count()
    safe_count = max(0, total_scans - phishing_count)

    latest_record = ScanRecord.query.filter_by(deleted=False).order_by(ScanRecord.id.desc()).first()
    latest_id = latest_record.id if latest_record else 0
    latest_threat = ScanRecord.query.filter_by(deleted=False).filter((ScanRecord.is_phishing == True) | (ScanRecord.threat_score >= 50)).order_by(ScanRecord.id.desc()).first()

    new_items = []
    if last_id > 0:
        new_q = ScanRecord.query.filter(ScanRecord.deleted == False, ScanRecord.id > last_id).order_by(ScanRecord.id.desc())
        new_items = [r.to_dict() for r in new_q.all()]

    page_records = query.order_by(ScanRecord.scanned_at.desc(), ScanRecord.id.desc()).limit(limit).all()

    return jsonify({
        "success": True,
        "latest_id": latest_id,
        "total_scans": total_scans,
        "phishing_count": phishing_count,
        "safe_count": safe_count,
        "latest_threat": latest_threat.to_dict() if latest_threat else None,
        "new_items_count": len(new_items),
        "new_items": new_items,
        "records": [r.to_dict() for r in page_records],
        "scanner_state": {
            "running": scanner_state.get("running", False),
            "account": os.getenv("EMAIL_ACCOUNT", ""),
            "last_scan": scanner_state.get("last_scan"),
            "last_scan_status": scanner_state.get("last_scan_status", "Ready")
        }
    })

@app.route('/api/record/<int:record_id>')
def get_record_api(record_id):
    rec = ScanRecord.query.get_or_404(record_id)
    return jsonify({
        "success": True,
        "record": rec.to_dict()
    })

@app.route('/api/simulate-email', methods=['POST'])
def simulate_email_api():
    data = request.get_json() or {}
    scenario = data.get("scenario", "paypal")

    scenarios = {
        "paypal": {
            "sender": "security-alert@paypa1-billing-update.com",
            "subject": "🚨 URGENT: Your PayPal account access has been restricted",
            "body": "Dear valued member,\n\nWe detected unauthorized activity from a strange device. You must verify your account immediately at http://paypa1-billing-update.com/verify or your account and linked bank account will be suspended permanently in 24 hours.\n\nPlease enter your login password and credit card number to confirm identity."
        },
        "netflix": {
            "sender": "billing-support@netflix-service-update.tk",
            "subject": "⚠️ Netflix: Payment declined - Service will be terminated",
            "body": "Hi Member,\n\nYour payment for this month was declined. Update your billing credentials now at http://netflix-service-update.tk/login?ref=failed to avoid permanent account termination and disconnection."
        },
        "ceo_wire": {
            "sender": "executive-director@globalcorporate-internal.cf",
            "subject": "Confidential Request: Immediate wire transfer needed",
            "body": "I am currently stuck in a confidential partner conference with limited cell reception. Need an emergency wire transfer of $38,500 sent to our vendor before 5:00 PM. Wire bank details immediately. Act now."
        },
        "lottery": {
            "sender": "claims-department@mega-international-lottery.ml",
            "subject": "🎉 CONGRATULATIONS! You won $2,500,000 in International Sweepstakes",
            "body": "You have been officially chosen as the grand prize winner! To claim your $2.5M prize, wire your processing fee and social security number to our agent immediately. Wire transfer details required."
        },
        "github_digest": {
            "sender": "notifications@github.com",
            "subject": "Your weekly GitHub Digest: Trending repositories in Python",
            "body": "Here is your weekly summary of trending repositories on https://github.com. Explore new AI machine learning tools and open-source packages. Everything is running smoothly. Happy coding!"
        },
        "zoom_invite": {
            "sender": "no-reply@zoom.us",
            "subject": "Invitation: Quarterly Security & Architecture Review",
            "body": "You are invited to Quarterly Security Review on Thursday at 3:00 PM. Join Zoom meeting: https://zoom.us/j/123456789. Meeting passcode: 456789. See you there."
        },
        "whatsapp_otp": {
            "sender": "[WhatsApp Support] +1 (555) 019-2831",
            "subject": "🚨 WhatsApp Alert: 6-Digit Verification Code Requested",
            "body": "Official WhatsApp Security Notification:\n\nSomeone requested a 6-digit registration code for your WhatsApp account from an unknown IP address. If this was not you, your account access will be terminated within 12 hours.\n\nPlease verify your identity immediately at: http://whatsapp-support-auth.com/verify?code=98214\n\nDo not share your verification code with anyone."
        },
        "whatsapp_lottery": {
            "sender": "[WhatsApp Rewards] +91 98765 43210",
            "subject": "🎉 Congratulations: You won ₹25,00,000 / $50,000 in WhatsApp Draw",
            "body": "Dear WhatsApp User,\n\nCongratulations! Your mobile number has won ₹25,00,000 ($30,000) in the 2026 KBC & WhatsApp International Mega Lucky Draw! To claim your cash prize directly in your bank account, send your photo and processing fee. Contact Manager Vijay Kumar immediately on WhatsApp: http://claim-whatsapp-rewards.ml/kbc\n\nAct now! Claim code: WIN779."
        },
        "whatsapp_job": {
            "sender": "[HR Global Recruiter] +44 7700 900077",
            "subject": "💼 Work from Home: Earn ₹3,000 - ₹8,000 Daily Liking Videos",
            "body": "Hello! We noticed your profile on LinkedIn. Our company is hiring part-time assistants. Task: Just like and subscribe to 3 YouTube videos per day. Payment: ₹500 per video, daily payout ₹3,000 - ₹8,000 via Google Pay / Paytm.\n\nClick here to chat with HR manager on WhatsApp: http://wa-chat-hr-recruitment.com/task?id=JOB889\n\nLimited spots available!"
        },
        "whatsapp_ebill": {
            "sender": "[Electricity Board Alert] +91 88776 65544",
            "subject": "⚠️ Urgent: Electricity Power Disconnection Notice",
            "body": "Dear Consumer, Your electricity power will be disconnected tonight at 9:30 PM from the power sub-station because your previous month bill was not updated. Please immediately contact our electricity officer Mr. Sharma at 8877665544 or pay pending bill online via: http://ebill-update-gov.in/pay. Urgent action required!"
        },
        "sms_loan_spam": {
            "sender": "[SMS/Spam] VK-QUICKLN (+91 91234 56780)",
            "subject": "🚨 Instant Pre-Approved Personal Loan of ₹5,00,000",
            "body": "Dear Customer, Congratulations! ₹5,00,000 pre-approved personal loan credited to your account! Zero CIBIL required. Disbursal in 5 minutes with 0% interest for 3 months. Click to claim cash now: http://bit.ly/instant-loan-cash"
        },
        "sms_parcel_smishing": {
            "sender": "[SMS/Smishing] AX-INPOST (+91 99887 11223)",
            "subject": "⚠️ India Post Package on Hold: Action Required",
            "body": "[India Post Alert] Your courier package (Item ID: IN-98214) is on hold at sorting hub due to incorrect street address. Please update your delivery address within 12 hours to avoid parcel return: http://indiapost-update-address.com/track"
        },
        "sms_kyc_spam": {
            "sender": "[SMS/Smishing] VK-SBIINB (+91 77665 44332)",
            "subject": "🚨 Bank Account KYC Suspension Notice",
            "body": "Dear SBI User, your YONO mobile banking and debit card have been suspended today due to pending KYC verification. Update your Aadhaar card and PAN number immediately at http://sbi-yono-kyc-auth.com to restore access."
        }
    }

    chosen = scenarios.get(scenario)
    if not chosen:
        chosen = {
            "sender": data.get("sender", "test-sender@example.com"),
            "subject": data.get("subject", "Test Security Alert"),
            "body": data.get("body", "Test email body content for phishing scanner.")
        }

    sender = chosen["sender"]
    subject = chosen["subject"]
    body = chosen["body"]

    analysis = process_email_analysis(subject, sender, body)
    
    if analysis["is_phishing"]:
        trigger_desktop_alert(sender, subject, analysis["threat_score"])

    scan_rec = ScanRecord(
        sender=sender,
        subject=subject,
        is_phishing=analysis["is_phishing"],
        threat_score=analysis["threat_score"],
        recommendations="\n".join(analysis["recommendations"])
    )
    db.session.add(scan_rec)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": f"Simulation executed: {'🚨 Phishing threat detected!' if analysis['is_phishing'] else '✅ Clean email verified'}",
        "record": scan_rec.to_dict(),
        "analysis": analysis
    })

@app.route('/api/analyze-url', methods=['POST'])
def analyze_url_api():
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"success": False, "error": "URL is required"}), 400
    res = analyze_url(url)
    return jsonify({"success": True, "result": res})

# =========================================================
# WhatsApp Sample Messages & Message Scanner API
# =========================================================
@app.route('/api/whatsapp/samples', methods=['GET'])
def get_whatsapp_samples():
    samples = [
        {
            "id": "wa_otp",
            "title": "Account Hijack / 6-Digit OTP Scam",
            "sender_name": "WhatsApp Security Team",
            "phone": "+1 (555) 019-2831",
            "time": "10:42 AM",
            "category": "High Risk Phishing",
            "threat_type": "danger",
            "score": "98%",
            "message": "🚨 [WhatsApp Official Security Alert] Someone requested a 6-digit registration code for your WhatsApp account from another device. If this was not you, your account will be disabled in 12 hours. Cancel this request and verify your phone number immediately at: http://whatsapp-support-auth.com/verify?code=98214. Do NOT share this code with anyone!"
        },
        {
            "id": "wa_lottery",
            "title": "KBC / WhatsApp International Lucky Draw",
            "sender_name": "KBC Mega Draw Department",
            "phone": "+91 98765 43210",
            "time": "11:15 AM",
            "category": "Advance Fee Fraud",
            "threat_type": "danger",
            "score": "94%",
            "message": "🎉 CONGRATULATIONS! Your WhatsApp number has won ₹25,00,000 ($30,000) in the 2026 KBC & WhatsApp International Mega Draw! To claim your cash prize directly in your bank account, wire your processing fee and contact Manager Vijay Kumar on WhatsApp: http://claim-whatsapp-rewards.ml/kbc. Offer valid for 24 hours only!"
        },
        {
            "id": "wa_job",
            "title": "Part-Time YouTube Like & Earn Job",
            "sender_name": "Global Recruitment HR",
            "phone": "+44 7700 900077",
            "time": "01:20 PM",
            "category": "Task / Investment Scam",
            "threat_type": "danger",
            "score": "95%",
            "message": "Hello! We noticed your profile on LinkedIn. Our company is hiring part-time assistants. Task: Just like and subscribe to 3 YouTube videos per day. Payment: ₹500 per video, daily payout ₹3,000 - ₹8,000 via Google Pay / Paytm. Click here to chat with HR manager on WhatsApp: http://wa-chat-hr-recruitment.com/task?id=JOB889. Limited slots!"
        },
        {
            "id": "wa_ebill",
            "title": "Urgent Electricity Power Disconnection",
            "sender_name": "Electricity Power Office",
            "phone": "+91 88776 65544",
            "time": "04:05 PM",
            "category": "Urgent Threat Scam",
            "threat_type": "danger",
            "score": "92%",
            "message": "Dear Consumer, Your electricity power will be disconnected tonight at 9:30 PM from the power station because your previous month bill was not updated. Please immediately contact our electricity officer Mr. Sharma at 8877665544 or pay pending bill online via: http://ebill-update-gov.in/pay. Urgent action required!"
        },
        {
            "id": "wa_clean",
            "title": "Legitimate Family Lunch Invitation",
            "sender_name": "Family & Friends Group",
            "phone": "+91 98234 56789",
            "time": "Yesterday",
            "category": "Verified Clean",
            "threat_type": "success",
            "score": "Clean 0%",
            "message": "Hey everyone! Are we still meeting for lunch tomorrow at 1:30 PM at the cafe? Please let me know who is coming so I can reserve the table. Looking forward to catching up with everyone!"
        }
    ]
    return jsonify(samples)

@app.route('/api/whatsapp/analyze', methods=['POST'])
def analyze_whatsapp_message():
    data = request.get_json() or {}
    message = data.get("message", "").strip()
    phone = data.get("phone", "+1-Unknown-Sender").strip()
    sender_name = data.get("sender_name", "WhatsApp Contact").strip()

    if not message:
        return jsonify({"success": False, "error": "Message text is required"}), 400

    subject = f"WhatsApp: {message[:50]}..."
    sender_display = f"[WhatsApp] {sender_name} ({phone})"

    analysis = process_email_analysis(subject, sender_display, message)

    if analysis["is_phishing"]:
        trigger_desktop_alert(sender_display, subject, analysis["threat_score"])

    scan_rec = ScanRecord(
        sender=sender_display,
        subject=subject,
        is_phishing=analysis["is_phishing"],
        threat_score=analysis["threat_score"],
        recommendations="\n".join(analysis["recommendations"])
    )
    db.session.add(scan_rec)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "🚨 Dangerous WhatsApp Phishing Scam Detected!" if analysis["is_phishing"] else "✅ Safe WhatsApp Message Verified",
        "record": scan_rec.to_dict(),
        "analysis": analysis,
        "phone": phone,
        "sender_name": sender_name
    })

# =========================================================
# SMS & Message Spam Classifier Engine & Endpoints
# =========================================================
def analyze_sms_spam(sender, message):
    spam_indicators = {
        "financial_loan": [
            "pre-approved", "instant loan", "zero interest", "no cibil", "apply loan",
            "credit limit", "disbursed", "congratulations loan", "instant cash"
        ],
        "reward_cashback": [
            "cashback", "credited to wallet", "claim reward", "won lottery", "free gift",
            "scratch card", "lucky draw", "free recharge", "bonus 500"
        ],
        "smishing_urgency": [
            "kyc blocked", "pan update", "account suspended", "sim blocked",
            "electricity disconnected", "power cutoff", "action required",
            "deactivated today", "update pan card", "yono account"
        ],
        "delivery_impersonation": [
            "package on hold", "delivery failed", "update address", "customs fee",
            "india post", "courier pending", "wrong house number"
        ],
        "gambling_betting": [
            "betting app", "color trading", "rummy bonus", "casino bonus",
            "earn daily", "apk download", "win 50000"
        ]
    }

    text_lower = message.lower()
    detected_categories = []
    detected_keywords = []

    for cat_name, kw_list in spam_indicators.items():
        found = [kw for kw in kw_list if kw in text_lower]
        if found:
            detected_categories.append(cat_name)
            detected_keywords.extend(found)

    urls = extract_urls(message)
    url_details = [analyze_url(u) for u in urls]
    has_malicious_url = any(u.get("is_malicious", False) for u in url_details)
    has_shortener = any("URL shortener detected" in u.get("issues", []) for u in url_details)

    bert_res = analyze_email_text(message)
    bert_score = float(bert_res["phishing_probability"])

    spam_score = bert_score * 0.45
    if detected_keywords:
        spam_score += min(35.0, len(detected_keywords) * 12.0)
    if urls:
        spam_score += 15.0
    if has_malicious_url or has_shortener:
        spam_score += 25.0

    is_mobile_number = bool(re.search(r'\+?\d{10,12}', sender.replace(" ", "").replace("-", "")))
    if is_mobile_number and ("bank" in text_lower or "kyc" in text_lower or "loan" in text_lower or "electricity" in text_lower or "post" in text_lower):
        spam_score += 20.0
        detected_keywords.append("Personal mobile number spoofing official organization")

    spam_score = min(100.0, max(0.0, round(spam_score, 1)))

    if spam_score >= 75:
        verdict = "SPAM_FRAUD"
        verdict_label = "🚨 CRITICAL SPAM / FRAUD"
        badge_color = "danger"
    elif spam_score >= 50:
        verdict = "SUSPICIOUS_SPAM"
        verdict_label = "⚠️ SUSPICIOUS SMISHING"
        badge_color = "warning"
    elif spam_score >= 25:
        verdict = "PROMOTIONAL"
        verdict_label = "📢 PROMOTIONAL / LOW RISK"
        badge_color = "info"
    else:
        verdict = "HAM_CLEAN"
        verdict_label = "🛡️ VERIFIED CLEAN (HAM)"
        badge_color = "success"

    recommendations = []
    if verdict in ("SPAM_FRAUD", "SUSPICIOUS_SPAM"):
        if urls:
            recommendations.append("DO NOT click any shortened links or download untrusted APKs.")
        if "financial_loan" in detected_categories or "reward_cashback" in detected_categories:
            recommendations.append("Genuine lenders never disburse loans without KYC documents and CIBIL checks.")
        if "smishing_urgency" in detected_categories:
            recommendations.append("Banks never notify account freeze via SMS requesting third-party site verification.")
        recommendations.append("Block this number immediately and report to Cyber Crime / 1909 DND.")
    else:
        recommendations.append("Message content conforms to standard transactional or conversational SMS.")

    return {
        "spam_score": spam_score,
        "is_spam": spam_score >= 50,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "badge_color": badge_color,
        "categories": detected_categories,
        "detected_keywords": list(set(detected_keywords)),
        "urls_found": len(urls),
        "url_details": url_details,
        "recommendations": recommendations,
        "bert_confidence": bert_res["confidence"]
    }

@app.route('/api/sms-spam/samples', methods=['GET'])
def get_sms_spam_samples():
    samples = [
        {
            "id": "sms_loan",
            "title": "Instant Personal Loan of ₹5,00,000",
            "sender": "VK-QUICKLN",
            "phone": "+91 91234 56780",
            "time": "Just now",
            "category": "Pre-Approved Loan Spam",
            "threat_type": "danger",
            "score": "96%",
            "message": "Dear Customer, Congratulations! ₹5,00,000 pre-approved personal loan credited to your account! Zero CIBIL required. Disbursal in 5 minutes with 0% interest for 3 months. Click to claim cash now: http://bit.ly/instant-loan-cash"
        },
        {
            "id": "sms_parcel",
            "title": "India Post Parcel On Hold Smishing",
            "sender": "AX-INPOST",
            "phone": "+91 99887 11223",
            "time": "12:20 PM",
            "category": "Delivery Impersonation Smishing",
            "threat_type": "danger",
            "score": "98%",
            "message": "[India Post Alert] Your courier package (Item ID: IN-98214) is on hold at sorting hub due to incorrect street address. Please update your delivery address within 12 hours to avoid parcel return: http://indiapost-update-address.com/track"
        },
        {
            "id": "sms_betting",
            "title": "Color Trading & Gambling APK Spam",
            "sender": "+91 98760 12345",
            "phone": "+91 98760 12345",
            "time": "10:15 AM",
            "category": "Gambling / Malicious APK Spam",
            "threat_type": "danger",
            "score": "94%",
            "message": "Deposit ₹100 and get ₹2,500 welcome bonus! Earn daily ₹5,000 playing Color Trading on fast withdrawal app. Instant UPI payout. Download official APK: http://colortrading-win.tk/app.apk"
        },
        {
            "id": "sms_cashback",
            "title": "Fake GPay / PhonePe ₹3,499 Reward",
            "sender": "DZ-REWARD",
            "phone": "+91 88770 99881",
            "time": "Yesterday",
            "category": "Cashback Fraud",
            "threat_type": "danger",
            "score": "95%",
            "message": "Congratulations! You have received ₹3,499 cashback reward from PhonePe/GooglePay. Offer expires in 2 hours. Click here to scratch card and claim direct to bank: http://reward-cashback-claim.ml"
        },
        {
            "id": "sms_kyc",
            "title": "Bank Account Suspension & PAN Smishing",
            "sender": "VK-SBIINB",
            "phone": "+91 77665 44332",
            "time": "Yesterday",
            "category": "Bank Smishing / Credential Theft",
            "threat_type": "danger",
            "score": "99%",
            "message": "Dear SBI User, your YONO mobile banking and debit card have been suspended today due to pending KYC verification. Update your Aadhaar card and PAN number immediately at http://sbi-yono-kyc-auth.com to restore access."
        },
        {
            "id": "sms_ham",
            "title": "Real Bank Transaction Alert (Clean Ham)",
            "sender": "VM-HDFCBK",
            "phone": "HDFC Bank Alert",
            "time": "2 days ago",
            "category": "Verified Bank Transaction",
            "threat_type": "success",
            "score": "Clean 0%",
            "message": "Rs 1,250.00 debited from A/c **4102 on 19-OCT-26 at SWIGGY BANGALORE. UPI Ref 429104829104. If not done by you, call 18002583838 or SMS BLOCK to 5676712."
        }
    ]
    return jsonify(samples)

@app.route('/api/sms-spam/analyze', methods=['POST'])
def analyze_sms_spam_api():
    data = request.get_json() or {}
    message = data.get("message", "").strip()
    sender = data.get("sender", "SMS Sender").strip()

    if not message:
        return jsonify({"success": False, "error": "Message content is required"}), 400

    analysis = analyze_sms_spam(sender, message)

    subject = f"SMS: {message[:50]}..."
    sender_display = f"[SMS/Spam] {sender}"

    if analysis["is_spam"]:
        trigger_desktop_alert(sender_display, subject, analysis["spam_score"])

    scan_rec = ScanRecord(
        sender=sender_display,
        subject=subject,
        is_phishing=analysis["is_spam"],
        threat_score=analysis["spam_score"],
        recommendations="\n".join(analysis["recommendations"])
    )
    db.session.add(scan_rec)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": f"{analysis['verdict_label']} ({analysis['spam_score']}%)",
        "record": scan_rec.to_dict(),
        "analysis": analysis,
        "sender": sender
    })

@app.route('/api/latest-threat')
def latest_threat_api():
    threat = ScanRecord.query.filter_by(deleted=False).filter((ScanRecord.is_phishing == True) | (ScanRecord.threat_score >= 50)).order_by(ScanRecord.id.desc()).first()
    if not threat:
        return jsonify({"found": False})
    return jsonify({
        "found": True,
        "id": threat.id,
        "sender": threat.sender,
        "subject": threat.subject,
        "threat_score": threat.threat_score,
        "scanned_at": threat.scanned_at.strftime("%Y-%m-%d %H:%M:%S") if threat.scanned_at else ""
    })

@app.route('/export')
def export_csv():
    import csv
    from io import StringIO
    si = StringIO()
    cw = csv.writer(si)
    records = ScanRecord.query.filter_by(deleted=False).order_by(ScanRecord.id.desc()).all()
    cw.writerow(['ID', 'Sender', 'Subject', 'Scanned At', 'Is Phishing', 'Threat Score', 'Recommendations'])
    for r in records:
        cw.writerow([r.id, r.sender, r.subject, r.scanned_at, r.is_phishing, r.threat_score, r.recommendations])
    output = si.getvalue()
    response = make_response(output)
    response.headers["Content-Disposition"] = "attachment; filename=phishshield_scan_report.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/export-json')
def export_json():
    records = ScanRecord.query.filter_by(deleted=False).order_by(ScanRecord.id.desc()).all()
    data = [r.to_dict() for r in records]
    resp = make_response(jsonify(data))
    resp.headers["Content-Disposition"] = "attachment; filename=phishshield_audit_report.json"
    resp.headers["Content-Type"] = "application/json"
    return resp

@app.route('/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    scan = ScanRecord.query.get_or_404(scan_id)
    scan.deleted = True
    db.session.commit()
    session['deleted_id'] = scan_id
    flash("Deleted. You can undo.", "warning")
    return redirect(request.referrer or url_for('scan_history'))

@app.route('/undo-delete/<int:scan_id>', methods=['POST'])
def undo_delete(scan_id):
    scan = ScanRecord.query.get_or_404(scan_id)
    scan.deleted = False
    db.session.commit()
    flash("Restored!", "success")
    return redirect(request.referrer or url_for('scan_history'))

@app.route('/api/test-samples', methods=['GET'])
def test_samples():
    samples = [
        {
            "id": 1,
            "subject": "URGENT: Verify your account immediately",
            "sender": "security@paypa1-verify.com",
            "body": "Your PayPal account has been limited. Click here to verify: [http://paypa1-verify.com/secure](http://paypa1-verify.com/secure). Verify within 24 hours or lose access.",
            "label": "phishing"
        },
        {
            "id": 2,
            "subject": "Your Amazon order #123-4567890",
            "sender": "auto-confirm@amazon.com",
            "body": "Hello, Your order has shipped! Track it: [https://amazon.com/track/xyz](https://amazon.com/track/xyz). Thank you!",
            "label": "legitimate"
        },
        {
            "id": 3,
            "subject": "You won $1,000,000!",
            "sender": "lottery@prize-winner.tk",
            "body": "CONGRATULATIONS! You won! Claim your prize: wire bank details and social security number now!",
            "label": "phishing"
        }
    ]
    return jsonify(samples)

# =========================================================
# In-App Background Scanner Engine & Endpoints
# =========================================================
scanner_thread = None
scanner_stop_event = threading.Event()
scanned_message_ids = set()

scanner_state = {
    "running": False,
    "account": os.getenv("EMAIL_ACCOUNT", ""),
    "last_scan": None,
    "last_scan_status": "Ready to scan.",
    "total_scanned_session": 0,
    "threats_found_session": 0,
    "scan_interval": int(os.getenv("SCAN_INTERVAL", "60"))
}

def trigger_desktop_alert(sender, subject, threat_score):
    if os.getenv("ENABLE_DESKTOP_NOTIFICATIONS", "true").lower() != "true":
        return
    try:
        from plyer import notification
        notification.notify(
            title="🚨 DANGER: PHISHING DETECTED!",
            message=f"Threat Score: {threat_score}%\nFrom: {sender[:35]}\n⚠️ DO NOT OPEN OR CLICK ANY LINKS!",
            app_name="PhishShield AI",
            timeout=10
        )
    except Exception as e:
        print(f"Desktop alert note: {e}")

def decode_mime_words(s):
    if not s:
        return ""
    decoded_fragments = decode_header(s)
    parts = []
    for text, enc in decoded_fragments:
        if isinstance(text, bytes):
            parts.append(text.decode(enc or "utf-8", errors="replace"))
        else:
            parts.append(str(text))
    return "".join(parts)

def extract_email_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" in content_disposition:
                continue
            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    body = payload.decode(errors="replace")
                    break
            elif content_type == "text/html" and not body:
                payload = part.get_payload(decode=True)
                if payload:
                    soup = BeautifulSoup(payload.decode(errors="replace"), "html.parser")
                    body = soup.get_text(separator=" ")
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            if content_type == "text/html":
                soup = BeautifulSoup(payload.decode(errors="replace"), "html.parser")
                body = soup.get_text(separator=" ")
            else:
                body = payload.decode(errors="replace")
    return body.strip()

def update_env_values(updates):
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    lines = []
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    existing_keys = set()
    new_lines = []
    for line in lines:
        if "=" in line and not line.strip().startswith("#"):
            k = line.split("=", 1)[0].strip()
            if k in updates:
                new_lines.append(f"{k}={updates[k]}\n")
                existing_keys.add(k)
                continue
        new_lines.append(line)
    for k, v in updates.items():
        if k not in existing_keys:
            new_lines.append(f"{k}={v}\n")
    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    for k, v in updates.items():
        os.environ[k] = str(v)

def run_single_scan_cycle():
    account = os.getenv("EMAIL_ACCOUNT", "").strip()
    password = os.getenv("EMAIL_APP_PASSWORD", "").strip()
    server = os.getenv("IMAP_SERVER", "imap.gmail.com").strip()
    port = int(os.getenv("IMAP_PORT", "993"))
    scan_full = os.getenv("SCAN_FULL_INBOX", "false").lower() == "true"
    max_emails = int(os.getenv("MAX_INBOX_EMAILS", "30"))

    if not account or not password:
        scanner_state["last_scan_status"] = "No email account configured."
        return 0, 0

    try:
        mail = imaplib.IMAP4_SSL(server, port, timeout=15)
        mail.login(account, password)
        mail.select("INBOX")
        search_crit = "ALL" if scan_full else "UNSEEN"
        status, messages = mail.search(None, search_crit)
        if status != "OK":
            mail.logout()
            return 0, 0

        msg_ids = messages[0].split()
        if scan_full and len(msg_ids) > max_emails:
            msg_ids = msg_ids[-max_emails:]

        new_count = 0
        threat_count = 0

        with app.app_context():
            for mid in msg_ids:
                uid_str = mid.decode()
                if uid_str in scanned_message_ids:
                    continue
                scanned_message_ids.add(uid_str)
                new_count += 1

                res, msg_data = mail.fetch(mid, "(RFC822)")
                if res != "OK":
                    continue
                raw_msg = email.message_from_bytes(msg_data[0][1])
                subj = decode_mime_words(raw_msg.get("Subject", "No Subject"))
                sndr = decode_mime_words(raw_msg.get("From", "Unknown Sender"))
                bdy = extract_email_body(raw_msg)

                analysis = process_email_analysis(subj, sndr, bdy or subj)
                if analysis["is_phishing"]:
                    threat_count += 1
                    trigger_desktop_alert(sndr, subj, analysis["threat_score"])
                    try:
                        mail.store(mid, '+FLAGS', '\\Flagged')
                    except Exception:
                        pass

                scan_rec = ScanRecord(
                    sender=sndr,
                    subject=subj,
                    is_phishing=analysis["is_phishing"],
                    threat_score=analysis["threat_score"],
                    recommendations="\n".join(analysis["recommendations"])
                )
                db.session.add(scan_rec)
                db.session.commit()

        mail.logout()
        scanner_state["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scanner_state["total_scanned_session"] += new_count
        scanner_state["threats_found_session"] += threat_count
        scanner_state["last_scan_status"] = f"Checked {len(msg_ids)} emails. Scanned {new_count} new ({threat_count} threats detected)."
        return new_count, threat_count
    except Exception as e:
        scanner_state["last_scan_status"] = f"Scan error: {str(e)}"
        return 0, 0

def background_scanner_worker():
    scanner_state["running"] = True
    interval = int(os.getenv("SCAN_INTERVAL", "60"))
    while not scanner_stop_event.is_set():
        run_single_scan_cycle()
        for _ in range(interval):
            if scanner_stop_event.is_set():
                break
            import time
            time.sleep(1)
    scanner_state["running"] = False

@app.route('/api/connect-email', methods=['POST'])
def connect_email_api():
    data = request.get_json() or {}
    email_acc = data.get('email', '').strip()
    app_pwd = data.get('password', '').strip().replace(' ', '')
    provider = data.get('provider', 'gmail').lower()
    
    server_map = {
        'gmail': 'imap.gmail.com',
        'outlook': 'outlook.office365.com',
        'yahoo': 'imap.mail.yahoo.com',
        'icloud': 'imap.mail.me.com'
    }
    server = server_map.get(provider, data.get('server', 'imap.gmail.com'))
    port = int(data.get('port', 993))

    if not email_acc or not app_pwd:
        return jsonify({"success": False, "error": "Email and 16-character App Password are required."}), 400

    try:
        mail = imaplib.IMAP4_SSL(server, port, timeout=12)
        mail.login(email_acc, app_pwd)
        mail.logout()
    except Exception as e:
        err = str(e)
        if "AUTHENTICATIONFAILED" in err or "Invalid credentials" in err or "Username and Password not accepted" in err:
            return jsonify({
                "success": False,
                "error": "Authentication Failed. For Gmail, you MUST use a 16-character App Password (not your regular Gmail password). Go to Google Account > Security > 2-Step Verification > App Passwords."
            }), 401
        return jsonify({"success": False, "error": f"Connection error: {err}"}), 400

    update_env_values({
        "EMAIL_ACCOUNT": email_acc,
        "EMAIL_APP_PASSWORD": app_pwd,
        "IMAP_SERVER": server,
        "IMAP_PORT": str(port),
        "NOTIFY_EMAIL": email_acc
    })
    scanner_state["account"] = email_acc
    scanner_state["last_scan_status"] = f"Connected to {email_acc}. Ready to scan."
    return jsonify({
        "success": True,
        "message": f"Successfully connected to {email_acc}! Auto-scanner can now be started."
    })

@app.route('/api/scanner/start', methods=['POST'])
def start_scanner_api():
    global scanner_thread
    if scanner_state["running"]:
        return jsonify({"success": True, "message": "Scanner is already running."})

    acc = os.getenv("EMAIL_ACCOUNT", "").strip()
    pwd = os.getenv("EMAIL_APP_PASSWORD", "").strip()
    if not acc or not pwd:
        return jsonify({"success": False, "error": "Please connect your email account first."}), 400

    scanner_stop_event.clear()
    scanner_thread = threading.Thread(target=background_scanner_worker, daemon=True)
    scanner_thread.start()
    return jsonify({"success": True, "message": f"1-Minute Auto-Scanner started for {acc}!"})

@app.route('/api/scanner/stop', methods=['POST'])
def stop_scanner_api():
    scanner_stop_event.set()
    scanner_state["running"] = False
    scanner_state["last_scan_status"] = "Scanner stopped by user."
    return jsonify({"success": True, "message": "Scanner stopped."})

@app.route('/api/scanner/status', methods=['GET'])
def get_scanner_status_api():
    scanner_state["account"] = os.getenv("EMAIL_ACCOUNT", "")
    return jsonify(scanner_state)

@app.route('/api/scanner/scan-now', methods=['POST'])
def scan_now_api():
    acc = os.getenv("EMAIL_ACCOUNT", "").strip()
    pwd = os.getenv("EMAIL_APP_PASSWORD", "").strip()
    if not acc or not pwd:
        return jsonify({"success": False, "error": "Please connect your email first."}), 400

    new_scanned, threats = run_single_scan_cycle()
    return jsonify({
        "success": True,
        "message": f"Scan completed: {new_scanned} emails analyzed, {threats} threats detected."
    })


def auto_start_scanner_if_configured():
    acc = os.getenv("EMAIL_ACCOUNT", "").strip()
    pwd = os.getenv("EMAIL_APP_PASSWORD", "").strip()
    if acc and pwd and not scanner_state["running"]:
        global scanner_thread
        scanner_stop_event.clear()
        scanner_thread = threading.Thread(target=background_scanner_worker, daemon=True)
        scanner_thread.start()
        print(f"[*] 1-Minute Auto-Scanner auto-started in background for {acc}")

# Auto-start background email scanner if credentials are configured
auto_start_scanner_if_configured()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() in ("1", "true")
    print("\n" + "="*50)
    print(f"PhishShield AI - Running on http://0.0.0.0:{port}")
    print(f"Open http://localhost:{port}/scan-history in your browser")
    print("="*50 + "\n")
    app.run(debug=debug_mode, use_reloader=False, host='0.0.0.0', port=port)