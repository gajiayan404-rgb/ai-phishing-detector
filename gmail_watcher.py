import os
import sys

# Ensure UTF-8 output on Windows console
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

import os.path
import pickle
import base64
import time
import requests
import re
import datetime
from dotenv import load_dotenv

load_dotenv()

# === Configuration ===
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "60"))  # Default 60 seconds (1 minute)
SCAN_FULL_INBOX = os.getenv("SCAN_FULL_INBOX", "false").lower() == "true"
MAX_INBOX_EMAILS = int(os.getenv("MAX_INBOX_EMAILS", "50"))
ENABLE_DESKTOP_NOTIFICATIONS = os.getenv("ENABLE_DESKTOP_NOTIFICATIONS", "true").lower() == "true"
NOTIFY_EMAIL = os.getenv("NOTIFY_EMAIL", "yourmail@example.com")
DETECTOR_API_URL = os.getenv("DETECTOR_API_URL", "http://localhost:5000/api/analyze")

# === Database logging dependencies ===
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Float, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class ScanRecord(Base):
    __tablename__ = 'scan_record'
    id = Column(Integer, primary_key=True, autoincrement=True)
    sender = Column(String(255))
    subject = Column(String(500))
    scanned_at = Column(DateTime, default=datetime.datetime.utcnow)
    is_phishing = Column(Boolean)
    threat_score = Column(Float)
    recommendations = Column(Text)
    deleted = Column(Boolean, default=False)

# Shared SQLite database in instance folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DB_PATH = os.path.join(INSTANCE_DIR, "scan_records.db")
engine = create_engine(f'sqlite:///{DB_PATH}')
Session = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

def log_scan_result(sender, subject, is_phishing, threat_score=None, recommendations=None):
    session = Session()
    scan = ScanRecord(
        sender=sender,
        subject=subject,
        scanned_at=datetime.datetime.utcnow(),
        is_phishing=is_phishing,
        threat_score=threat_score,
        recommendations="\n".join(recommendations) if recommendations else "",
        deleted=False
    )
    session.add(scan)
    session.commit()
    print(f"  [DB LOG] {sender} | Subj: {subject[:40]} | Phishing: {is_phishing} | Score: {threat_score}")
    session.close()

# === Desktop Notification ===
def send_desktop_alert(sender, subject, threat_score):
    if not ENABLE_DESKTOP_NOTIFICATIONS:
        return
    try:
        from plyer import notification
        notification.notify(
            title="🚨 DANGER: PHISHING DETECTED!",
            message=f"Threat Score: {threat_score}%\nFrom: {sender[:35]}\n⚠️ DO NOT OPEN OR CLICK ANY LINKS!",
            app_name="PhishShield AI",
            timeout=10
        )
        print("  -> [DESKTOP ALERT] Windows notification displayed!")
    except Exception as e:
        print(f"  -> Desktop notification note: {e}")

# === Gmail Config & Whitelists ===
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.mime.text import MIMEText

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
]

NO_REPLY_LIST = [
    'noreply', 'no-reply', 'donotreply', 'do-not-reply', 'notification', 'notifications',
    'mailer-daemon', 'automated', 'auto', 'autoresponder', 'auto-reply', 'auto_response',
    'system', 'robot', 'postmaster', 'bounce', 'bounces', 'nobody', 'no_reply', 'noreplies',
    'alerts', 'alert', 'announce', 'announcement', 'update', 'updates', 'support', 'helpdesk',
    'info', 'information', 'service', 'admin', 'administrator', 'do_not_reply', 'please_do_not_reply',
    'replyto', 'reply_to', 'unsubscribe', 'events', 'request', 'ticket', 'invoice', 'billing',
    'receipt', 'order', 'sales', 'accounts', 'account', 'customerservice', 'customersupport',
    'contactus', 'team', 'survey', 'bulkmail', 'reminder', 'reminders', 'scheduled', 'listserv',
    'marketing', 'optout', 'opt-out', 'feedback', 'confirm', 'confirmation', 'passwordreset',
    'reset', 'verif', 'verification', 'norespond', 'no_response'
]

TRUSTED_DOMAINS = [
    "youtube.com", "youtu.be", "google.com", "gmail.com", "outlook.com",
    "microsoft.com", "apple.com", "icloud.com", "amazon.com", "ebay.com",
    "paypal.com", "linkedin.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "reddit.com", "github.com", "stackoverflow.com",
    "wikipedia.org", "nytimes.com", "bbc.com", "cnn.com", "wsj.com",
    "slack.com", "zoom.us", "dropbox.com", "box.com", "drive.google.com",
    "docs.google.com", "medium.com", "office.com", "live.com", "aol.com",
    "protonmail.com", "duckduckgo.com", "quora.com", "netflix.com", "hulu.com",
    "disneyplus.com", "hotstar.com", "spotify.com", "adobe.com", "xda-developers.com",
    "wordpress.com", "blogger.com", "skype.com", "twitch.tv", "roblox.com",
    "steamcommunity.com", "steampowered.com", "oracle.com", "ibm.com", "intel.com",
    "phillips.com", "samsung.com", "sony.com", "lg.com", "dell.com", "hp.com",
    "lenovo.com", "asus.com", "nvidia.com", "amd.com", "uber.com", "airbnb.com",
    "booking.com", "expedia.com", "trivago.com", "makemytrip.com", "tripadvisor.com",
    "zomato.com", "swiggy.com", "flipkart.com", "snapdeal.com", "bigbasket.com",
    "whatsapp.com", "telegram.org", "signal.org", "tumblr.com", "flickr.com",
    "pinterest.com", "imgur.com", "canva.com", "coursera.org", "udemy.com",
    "edx.org", "khanacademy.org", "tiktok.com", "vimeo.com", "jiomart.com",
    "openai.com", "bard.google.com", "huggingface.co", "bitbucket.org"
]

def extract_urls(text):
    url_pattern = r'https?://[^\s<>()"]+'
    return re.findall(url_pattern, text)

def is_trusted_url(url):
    for domain in TRUSTED_DOMAINS:
        if domain.lower() in url.lower():
            return True
    return False

def all_urls_trusted(body):
    urls = extract_urls(body)
    if not urls:
        return True
    return all(is_trusted_url(url) for url in urls)

def gmail_authenticate():
    creds = None
    token_path = os.path.join(BASE_DIR, "token.pickle")
    credentials_path = os.path.join(BASE_DIR, "credentials.json")
    if os.path.exists(token_path):
        with open(token_path, "rb") as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(credentials_path):
                print("\n[!] credentials.json not found!")
                print("    To connect via Gmail OAuth, download your credentials.json from Google Cloud Console.")
                print("    Alternatively, use the Universal IMAP scanner: python imap_watcher.py\n")
                sys.exit(1)
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(token_path, "wb") as token:
            pickle.dump(creds, token)
    return build("gmail", "v1", credentials=creds)

def list_messages(service, scan_full_inbox=False, max_count=50):
    try:
        label_ids = ["INBOX"] if scan_full_inbox else ["INBOX", "UNREAD"]
        results = service.users().messages().list(
            userId="me",
            labelIds=label_ids,
            maxResults=max_count
        ).execute()
        return results.get("messages", [])
    except HttpError as error:
        print(f"An error occurred: {error}")
        return []

def get_email_content(service, msg_id):
    msg = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
    headers = msg["payload"].get("headers", [])
    subject = next((h["value"] for h in headers if h["name"] == "Subject"), "")
    sender = next((h["value"] for h in headers if h["name"] == "From"), "")
    parts = msg["payload"].get("parts", [])
    body = ""
    for part in parts:
        if part.get("mimeType") == "text/plain":
            body_data = part["body"].get("data")
            if body_data:
                body = base64.urlsafe_b64decode(body_data).decode("utf-8", errors="replace")
                break
    if not body and "body" in msg["payload"] and "data" in msg["payload"]["body"]:
        body = base64.urlsafe_b64decode(msg["payload"]["body"]["data"]).decode("utf-8", errors="replace")
    return subject, sender, body

def skip_sender(sender):
    sender = sender.lower()
    return any(bad in sender for bad in NO_REPLY_LIST)

def analyze_email(subject, sender, body):
    data = {
        "subject": subject,
        "sender": sender,
        "email_text": body or subject,
    }
    try:
        response = requests.post(DETECTOR_API_URL, json=data, timeout=30)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error analyzing email: {response.text}")
            return None
    except Exception as e:
        print(f"Error connecting to detection API: {str(e)}")
        return None

def add_result_label(service, msg_id, is_phishing):
    # Distinct Red Warning label for Phishing
    label_name = "🚨 DANGER: PHISHING - DO NOT OPEN" if is_phishing else "PhishScanAI-Safe"
    labels = service.users().labels().list(userId='me').execute().get('labels', [])
    label_id = None
    for lbl in labels:
        if lbl['name'] == label_name:
            label_id = lbl['id']
            break
    if not label_id:
        label_obj = {
            'name': label_name,
            'labelListVisibility': 'labelShow',
            'messageListVisibility': 'show'
        }
        if is_phishing:
            # Highlight with red in Gmail
            label_obj['color'] = {
                'backgroundColor': '#fb4c4c',
                'textColor': '#ffffff'
            }
        else:
            label_obj['color'] = {
                'backgroundColor': '#16a765',
                'textColor': '#ffffff'
            }
        try:
            label = service.users().labels().create(userId='me', body=label_obj).execute()
            label_id = label['id']
        except Exception:
            # Fallback without color if color palette fails
            try:
                label = service.users().labels().create(userId='me', body={'name': label_name}).execute()
                label_id = label['id']
            except Exception as e:
                print(f"Could not create label: {e}")
                return
    try:
        service.users().messages().modify(userId="me", id=msg_id, body={"addLabelIds": [label_id]}).execute()
        print(f"  -> Applied label: '{label_name}' to email {msg_id}")
    except HttpError as error:
        print(f"Could not label message {msg_id}: {error}")

def send_report(service, to_email, subject, body_text):
    if not to_email or "example.com" in to_email:
        return
    message = MIMEText(body_text)
    message["to"] = to_email
    message["from"] = "me"
    message["subject"] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    message_body = {"raw": raw_message}
    try:
        sent_msg = service.users().messages().send(userId="me", body=message_body).execute()
        print(f"  -> Notification email sent to {to_email}: ID {sent_msg['id']}")
    except HttpError as error:
        print(f"An error occurred sending notification email: {error}")

def main():
    service = gmail_authenticate()
    print("=" * 65)
    print("🛡️  PhishShield AI - Gmail Inbox Auto-Scanner")
    print(f"   Scan Interval : Every {SCAN_INTERVAL} seconds ({SCAN_INTERVAL // 60} minute)")
    print(f"   Scan Target   : {'FULL INBOX' if SCAN_FULL_INBOX else 'UNREAD MESSAGES ONLY'}")
    print(f"   Desktop Alerts: {'ENABLED' if ENABLE_DESKTOP_NOTIFICATIONS else 'DISABLED'}")
    print("=" * 65)

    scanned_ids = set()

    while True:
        cycle_time = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"\n[{cycle_time}] Checking inbox for emails...")
        messages = list_messages(service, scan_full_inbox=SCAN_FULL_INBOX, max_count=MAX_INBOX_EMAILS)

        new_count = 0
        for msg in messages:
            msg_id = msg["id"]
            if msg_id in scanned_ids:
                continue

            scanned_ids.add(msg_id)
            new_count += 1

            subject, sender, body = get_email_content(service, msg_id)
            print(f"\n[SCAN] From: {sender} | Subj: {subject[:50]}")

            if skip_sender(sender):
                print("  -> Skipping system/automated sender")
                add_result_label(service, msg_id, False)
                log_scan_result(sender, subject, False, 0.0, ["Skipped automated sender"])
                continue

            result = analyze_email(subject, sender, body)
            if not result:
                continue

            is_phishing = result.get("is_phishing", False)
            threat_score = result.get("threat_score", 0.0)

            # Trusted domain verification
            if is_phishing and all_urls_trusted(body):
                print("  -> Overridden: All contained URLs belong to verified trusted domains")
                is_phishing = False

            if is_phishing:
                print(f"  🚨 [RED ALERT] PHISHING DETECTED! Threat Score: {threat_score}%")
                # 1. Desktop Notification
                send_desktop_alert(sender, subject, threat_score)

                # 2. Email Notification to secondary address
                report_body = (
                    f"🚨 CRITICAL PHISHING ALERT - DO NOT OPEN!\n\n"
                    f"Subject: {subject}\n"
                    f"Sender: {sender}\n"
                    f"Threat Score: {threat_score}%\n\n"
                    f"Recommendations:\n- " + "\n- ".join(result.get("recommendations", []))
                )
                send_report(service, NOTIFY_EMAIL, "🚨 PhishShield Alert: Fake / Scam Email Detected", report_body)
            else:
                print(f"  ✅ Email appears Safe (Threat Score: {threat_score}%)")

            # 3. Label email in Gmail (Red Warning Label)
            add_result_label(service, msg_id, is_phishing)

            # 4. Log to Shared Database
            log_scan_result(
                sender=sender,
                subject=subject,
                is_phishing=is_phishing,
                threat_score=threat_score,
                recommendations=result.get('recommendations')
            )

        if new_count == 0:
            print("  No new unscanned messages found.")
        else:
            print(f"  Scanned {new_count} new email(s).")

        print(f"Waiting {SCAN_INTERVAL}s until next scan cycle... (Press Ctrl+C to stop)")
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main()