import os
import sys

# Ensure UTF-8 output on Windows console
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

import imaplib
import email
from email.header import decode_header
import time
import requests
import datetime
from dotenv import load_dotenv
from bs4 import BeautifulSoup

load_dotenv()

# === Configuration ===
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "60"))  # Default 60 seconds (1 minute)
SCAN_FULL_INBOX = os.getenv("SCAN_FULL_INBOX", "false").lower() == "true"
MAX_INBOX_EMAILS = int(os.getenv("MAX_INBOX_EMAILS", "30"))
ENABLE_DESKTOP_NOTIFICATIONS = os.getenv("ENABLE_DESKTOP_NOTIFICATIONS", "true").lower() == "true"
DETECTOR_API_URL = os.getenv("DETECTOR_API_URL", "http://localhost:5000/api/analyze")

IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))
EMAIL_ACCOUNT = os.getenv("EMAIL_ACCOUNT", "")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD", "")

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

def extract_body(msg):
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
            print(f"  Error analyzing email: {response.text}")
            return None
    except Exception as e:
        print(f"  Error connecting to detection API: {str(e)}")
        return None

def connect_imap():
    server = IMAP_SERVER
    port = IMAP_PORT
    account = EMAIL_ACCOUNT
    password = EMAIL_APP_PASSWORD

    if not account or not password:
        print("\n" + "=" * 65)
        print("Universal IMAP Email Connector")
        print("Connect ANY email account (Gmail, Outlook, Yahoo, etc.)")
        print("=" * 65)
        account = input("Enter your email address: ").strip()
        password = input("Enter your App Password: ").strip()
        custom_server = input(f"Enter IMAP server [{server}]: ").strip()
        if custom_server:
            server = custom_server

    print(f"\nConnecting to {server}:{port} as {account}...")
    mail = imaplib.IMAP4_SSL(server, port)
    mail.login(account, password)
    print("Authentication successful!")
    return mail

def main():
    print("=" * 65)
    print("🛡️  PhishShield AI - Universal Email Auto-Scanner (IMAP)")
    print(f"   Scan Interval : Every {SCAN_INTERVAL} seconds ({SCAN_INTERVAL // 60} minute)")
    print(f"   Scan Target   : {'FULL INBOX' if SCAN_FULL_INBOX else 'UNREAD MESSAGES ONLY'}")
    print(f"   Desktop Alerts: {'ENABLED' if ENABLE_DESKTOP_NOTIFICATIONS else 'DISABLED'}")
    print("=" * 65)

    mail = connect_imap()
    scanned_uids = set()

    while True:
        try:
            mail.select("INBOX")
            search_criterion = "ALL" if SCAN_FULL_INBOX else "UNSEEN"
            status, messages = mail.search(None, search_criterion)

            if status != "OK":
                print("Could not retrieve messages.")
                time.sleep(SCAN_INTERVAL)
                continue

            msg_ids = messages[0].split()
            # If full inbox, limit to the most recent messages
            if SCAN_FULL_INBOX and len(msg_ids) > MAX_INBOX_EMAILS:
                msg_ids = msg_ids[-MAX_INBOX_EMAILS:]

            cycle_time = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"\n[{cycle_time}] Checking inbox... ({len(msg_ids)} eligible email(s) found)")

            new_count = 0
            for msg_id in msg_ids:
                uid_str = msg_id.decode()
                if uid_str in scanned_uids:
                    continue

                scanned_uids.add(uid_str)
                new_count += 1

                res, msg_data = mail.fetch(msg_id, "(RFC822)")
                if res != "OK":
                    continue

                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                subject = decode_mime_words(msg.get("Subject", "No Subject"))
                sender = decode_mime_words(msg.get("From", "Unknown Sender"))
                body = extract_body(msg)

                print(f"\n[SCAN] From: {sender} | Subj: {subject[:45]}")
                result = analyze_email(subject, sender, body)

                if not result:
                    continue

                is_phishing = result.get("is_phishing", False)
                threat_score = result.get("threat_score", 0.0)

                if is_phishing:
                    print(f"  🚨 [RED ALERT] PHISHING DETECTED! Threat Score: {threat_score}%")
                    # 1. Desktop Notification
                    send_desktop_alert(sender, subject, threat_score)

                    # 2. Flag message in inbox as high alert
                    try:
                        mail.store(msg_id, '+FLAGS', '\\Flagged')
                    except Exception:
                        pass
                else:
                    print(f"  ✅ Safe email (Threat Score: {threat_score}%)")

                # 3. Log to shared SQLite database
                log_scan_result(
                    sender=sender,
                    subject=subject,
                    is_phishing=is_phishing,
                    threat_score=threat_score,
                    recommendations=result.get("recommendations", [])
                )

            if new_count == 0:
                print("  No new unscanned messages found.")
            else:
                print(f"  Scanned {new_count} new email(s).")

        except imaplib.IMAP4.abort as e:
            print(f"IMAP connection dropped: {e}. Reconnecting...")
            try:
                mail = connect_imap()
            except Exception as re_err:
                print(f"Reconnection failed: {re_err}")
        except Exception as e:
            print(f"Scan cycle error: {e}")

        print(f"Waiting {SCAN_INTERVAL}s until next scan cycle... (Press Ctrl+C to stop)")
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main()
