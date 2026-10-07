import sqlite3
import os
import json
from datetime import datetime

DB_FILE = os.path.join(os.path.dirname(__file__), 'qrshield.db')

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            qr_content TEXT NOT NULL,
            qr_type TEXT NOT NULL,
            detected_action TEXT NOT NULL,
            destination TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            info_requested TEXT,
            security_checks TEXT,
            explanation TEXT NOT NULL,
            user_decision TEXT NOT NULL,
            is_demo INTEGER DEFAULT 0
        )
    ''')
    
    # Check if empty, insert default recent scans as requested in prompt:
    # "Payment QR — LOW, Registration Form — MEDIUM, Login QR — HIGH"
    cursor.execute('SELECT COUNT(*) FROM scans')
    count = cursor.fetchone()[0]
    
    if count == 0:
        seed_scans = [
            (
                datetime.now().strftime("%Y-%m-%d %H:%M"),
                "upi://pay?pa=merchant@okaxis&pn=CampusStore&am=250.00&cu=INR",
                "Payment",
                "UPI Payment",
                "merchant@okaxis (Verified Merchant)",
                "LOW",
                10,
                json.dumps(["Transaction Amount", "Payee VPA"]),
                json.dumps({
                    "https": {"status": "safe", "label": "VPA Verification", "detail": "Valid merchant address format"},
                    "domain": {"status": "safe", "label": "Protocol Safety", "detail": "Encrypted UPI schema"},
                    "redirects": {"status": "safe", "label": "Direct Action", "detail": "No intermediate hopping"},
                    "suspicious_url": {"status": "safe", "label": "Payload Integrity", "detail": "Standard banking syntax"},
                    "reputation": {"status": "safe", "label": "Merchant Trust", "detail": "Known retail provider"},
                    "sensitive_data": {"status": "safe", "label": "Data Exposure", "detail": "No credentials exposed"}
                }),
                "Standard encrypted payment payload with no suspicious parameters or credential requests.",
                "Continued",
                1
            ),
            (
                datetime.now().strftime("%Y-%m-%d %H:%M"),
                "https://hackathon-reg.example-college.edu/register?event=hack2026",
                "Registration",
                "Form Submission",
                "hackathon-reg.example-college.edu",
                "MEDIUM",
                45,
                json.dumps(["Full Name", "Email Address", "Phone Number", "College Student ID"]),
                json.dumps({
                    "https": {"status": "safe", "label": "HTTPS Protocol", "detail": "Valid SSL certificate detected"},
                    "domain": {"status": "warning", "label": "Domain Consistency", "detail": "Third-party subdomain detected"},
                    "redirects": {"status": "safe", "label": "Direct Destination", "detail": "No hidden redirects"},
                    "suspicious_url": {"status": "safe", "label": "URL Structure", "detail": "Standard query parameters"},
                    "reputation": {"status": "safe", "label": "Domain Reputation", "detail": "Neutral reputation score"},
                    "sensitive_data": {"status": "warning", "label": "PII Collection", "detail": "Requests name, phone, and student ID"}
                }),
                "Personal identifiable information (PII) is requested before accessing the event platform.",
                "Continued",
                1
            ),
            (
                datetime.now().strftime("%Y-%m-%d %H:%M"),
                "https://secure-login.portal-verification-auth.top/signin?redirect=session_update",
                "Login",
                "Login / Credential Submission",
                "secure-login.portal-verification-auth.top",
                "HIGH",
                85,
                json.dumps(["Username / Email", "Account Password", "2FA Security Code"]),
                json.dumps({
                    "https": {"status": "safe", "label": "HTTPS Protocol", "detail": "Active SSL certificate (Free Let's Encrypt)"},
                    "domain": {"status": "risk", "label": "Domain Consistency", "detail": "Suspicious typo-squatted domain pattern"},
                    "redirects": {"status": "risk", "label": "Redirect Tracing", "detail": "Multiple intermediate redirects detected"},
                    "suspicious_url": {"status": "risk", "label": "URL Structure", "detail": "High-risk TLD (.top) with excessive hyphens"},
                    "reputation": {"status": "risk", "label": "Reputation Check", "detail": "Newly registered domain (< 48 hrs)"},
                    "sensitive_data": {"status": "risk", "label": "Credential Harvesting", "detail": "Requests master password on unverified portal"}
                }),
                "Destination exhibits high-risk phishing indicators, suspicious domain patterning, and active credential harvesting fields.",
                "Cancelled",
                1
            )
        ]
        
        cursor.executemany('''
            INSERT INTO scans (
                timestamp, qr_content, qr_type, detected_action, destination,
                risk_level, risk_score, info_requested, security_checks,
                explanation, user_decision, is_demo
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', seed_scans)
        
    conn.commit()
    conn.close()

def insert_scan(data):
    conn = get_db()
    cursor = conn.cursor()
    
    timestamp = data.get('timestamp') or datetime.now().strftime("%Y-%m-%d %H:%M")
    qr_content = data.get('qr_content', '')
    qr_type = data.get('qr_type', 'Unknown')
    detected_action = data.get('detected_action', 'Unknown Action')
    destination = data.get('destination', '')
    risk_level = data.get('risk_level', 'LOW')
    risk_score = data.get('risk_score', 0)
    info_requested = json.dumps(data.get('info_requested', []))
    security_checks = json.dumps(data.get('security_checks', {}))
    explanation = data.get('explanation', '')
    user_decision = data.get('user_decision', 'Pending')
    is_demo = 1 if data.get('is_demo', False) else 0
    
    cursor.execute('''
        INSERT INTO scans (
            timestamp, qr_content, qr_type, detected_action, destination,
            risk_level, risk_score, info_requested, security_checks,
            explanation, user_decision, is_demo
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        timestamp, qr_content, qr_type, detected_action, destination,
        risk_level, risk_score, info_requested, security_checks,
        explanation, user_decision, is_demo
    ))
    
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_scans(risk_filter=None, limit=50):
    conn = get_db()
    cursor = conn.cursor()
    
    if risk_filter and risk_filter.upper() != 'ALL':
        cursor.execute(
            'SELECT * FROM scans WHERE UPPER(risk_level) = ? ORDER BY id DESC LIMIT ?',
            (risk_filter.upper(), limit)
        )
    else:
        cursor.execute('SELECT * FROM scans ORDER BY id DESC LIMIT ?', (limit,))
        
    rows = cursor.fetchall()
    results = []
    for r in rows:
        item = dict(r)
        try:
            item['info_requested'] = json.loads(item['info_requested']) if item['info_requested'] else []
        except Exception:
            item['info_requested'] = []
        try:
            item['security_checks'] = json.loads(item['security_checks']) if item['security_checks'] else {}
        except Exception:
            item['security_checks'] = {}
        results.append(item)
        
    conn.close()
    return results

def get_stats():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM scans')
    total = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'HIGH'")
    high = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'MEDIUM'")
    medium = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'LOW'")
    low = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE user_decision = 'Cancelled' AND risk_level IN ('HIGH', 'MEDIUM')")
    blocked = cursor.fetchone()[0]
    
    conn.close()
    return {
        'total_scans': total,
        'high_risk': high,
        'medium_risk': medium,
        'low_risk': low,
        'threats_blocked': blocked or high
    }

def clear_scans():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scans')
    conn.commit()
    conn.close()
