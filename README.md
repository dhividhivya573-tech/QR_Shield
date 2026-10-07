# 🛡️ QR Shield

> **"Scan it. Understand it. Then Act."**  
> *A pre-action security layer for QR interactions.*

---

## 🌟 The Problem & Vision

Traditional QR scanners suffer from a fundamental security flaw:
```
Traditional:  [ Scan QR ] ➔ [ Decode URL ] ➔ [ ⚠️ Open Destination Blindly ]
```
When a user scans a physical or digital QR code, traditional scanner apps immediately decode the URL and instruct the browser to open it without inspection. Attackers exploit this blind trust via **Quishing** (QR Phishing), directing victims to:
- Spoofed institutional and banking login portals
- Malicious drive-by file downloads (`.apk`, `.exe`, `.dmg`)
- Hidden redirection chains and URL shorteners
- Unauthorized monetary transaction and UPI authorization requests

### The QR Shield Solution
```
QR Shield:    [ Scan QR ] ➔ [ 🛡 Deep Analysis ] ➔ [ 🔎 Action Preview ] ➔ [ ⚖️ Decide ]
```
QR Shield acts as a **zero-trust inspection sandbox**. It decodes the payload, classifies the intended action, inspects 6 core security vectors, computes an explainable risk score, and displays an understandable **Action Preview** before opening any external destination.

**The destination is NEVER opened automatically.**

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+ (Python 3.14 recommended)
- Modern web browser (Chrome, Edge, Firefox, Safari)

### 1-Click Launch (Windows)
Double-click `run.bat` or run:
```bash
python app.py
```
Open your browser at:  
👉 **`http://127.0.0.1:5000`**

### Running Automated Test Suite
```bash
python -m unittest tests/test_qrshield.py
```

---

## 🖥️ User Experience & Key Screens

### 1. 🏠 Home Dashboard
- **Tagline Banner**: *"Scan it. Understand it. Then Act."*
- **Paradigm Comparison**: Prominent side-by-side contrast of Traditional Scanners vs QR Shield.
- **Workflow Overview**: 5-step visual guide (Detects type, Understands action, Checks security, Shows preview, Lets user choose).
- **Telemetry Counters**: Total Scans, Threats Intercepted, High Risk detections, Clean Pass Rate.
- **Recent Scans Feed**: Live status table pre-populated with realistic security interactions:
  - *Payment QR* — **LOW**
  - *Registration Form* — **MEDIUM**
  - *Suspicious Login* — **HIGH**

### 2. 📷 QR Scanner Screen
- **Camera Viewfinder**: Real-time camera feed with cyber HUD targeting brackets and animated laser scanline.
- **Image Upload Dropzone**: Drag-and-drop or file upload supporting `.png`, `.jpg`, `.webp`.
- **Manual Payload Tester**: Input field to test arbitrary URLs, UPI strings, or payloads directly.
- **Animated Cyber Analysis Sequence**:
  - `✓ QR decoded`
  - `✓ QR type detected`
  - `✓ Destination analysed`
  - `✓ Security checked`
  - `✓ Action identified`

### 3. 🔎 Action Preview Screen (The Core Interface)
Features **TWO Action Preview Modes**:
1. **MODE 1 — DEMO ACTION PREVIEW**: Pre-configured mock scenarios with deterministic threat parameters for hackathon evaluation.
2. **MODE 2 — REAL QR SCAN ACTION PREVIEW**: Live pre-action deep inspection with heuristic content extraction, real-time HTTP redirect tracing, and form field analysis.

- **Mode Badge Indicator**: Displays `MODE 1 — DEMO ACTION PREVIEW` or `MODE 2 — REAL QR SCAN ACTION PREVIEW`.
- **Large Glowing Risk Badge**:
  - 🟢 **LOW RISK** (`0–30` pts)
  - 🟡 **MEDIUM RISK** (`31–60` pts)
  - 🔴 **HIGH RISK** (`61+` pts)
  - ⚠️ **LIMITED ANALYSIS / UNKNOWN** (when external site blocks inspection)
- **Payment Breakdown Card (UPI & Payment QRs)**:
  - *Merchant / Payee Name* (extracted from `pn` or UPI ID)
  - *Transaction Amount* (e.g., `₹2,000` or explicitly `"Not specified in QR"` without inventing values)
  - *UPI ID / Destination* (extracted from `pa`)
  - *Transaction Note* (if present in `tn`)
- **Intended Action Card**: Identifies clear intent (e.g., *Payment*, *Registration Form*, *Login*, *Website*, *Download*, *Wi-Fi Connection*).
- **Destination Card**: Full domain and URL endpoint with one-click copy.
- **Information Requested Tags**:
  - Real form analysis: Only displays fields actually detected on the page (e.g. `✓ Name`, `✓ Email`, `✓ Phone`, `✓ College ID`).
  - Login analysis: `✓ Username / Email`, `✓ Password`.
- **Security Analysis Matrix (Checks with ✓ Safe, ⚠ Warning, ✕ Risk)**:
  1. **HTTPS Status** (TLS encryption validation)
  2. **Domain Consistency** (Checks for Punycode homographs, IP hosts, excessive subdomains, brand typo-squatting)
  3. **Redirect Detection** (Follows live HTTP redirects and flags intermediate hops/shorteners)
  4. **Suspicious URL Pattern** (Character entropy, repetitive lures, credential tricks)
  5. **Reputation Status** (Domain history heuristics, abusive TLDs)
  6. **Sensitive Information / Credential Request** (PII collection vs credential harvesting)
- **"Why this risk?" Section**: Transparent security explanation detailing exact factors detected.
- **Continue Flow (Zero-Trust Confirmation)**:
  - Clicking `[ Continue ]` never immediately opens the destination or triggers payment.
  - Opens a confirmation dialog:
    - *For Payment:* "You are about to continue to this payment destination." with merchant and amount confirmation.
    - *For Other URLs:* "You are about to navigate to: `<destination>`".
    - User explicitly clicks `[ Proceed ]` or `[ Go Back ]`.
- **Cancel Flow**:
  - Clicking `[ Cancel ]` displays:
    `🛡️ ACTION CANCELLED`
    *"The destination was not opened."*
    `[ Back to Dashboard ]` button.

### 4. ⚡ Demo Mode & Security Lab
Includes the 3 hackathon demo scenarios:
- **Demo 1 — Demo Payment QR**:
  - *Action:* Payment | *Merchant:* ABC Store | *Amount:* ₹2,000 | *Destination:* `abc-pay.example`
  - *Security Checks:* HTTPS: ✓ | Domain Consistency: ⚠ | Redirect: ⚠ | Reputation: ✓
  - *Risk:* 🟡 **MEDIUM**
  - *Why this risk:* “Domain consistency and redirect indicators require attention.”
- **Demo 2 — Demo Registration QR**:
  - *Action:* Registration Form | *Destination:* `registration.example`
  - *Information Requested:* `✓ Name`, `✓ Email`, `✓ Phone Number`, `✓ College ID`
  - *Risk:* 🟡 **MEDIUM**
  - *Why this risk:* “Personal information is requested before form submission.”
- **Demo 3 — Demo Suspicious Login QR**:
  - *Action:* Login | *Destination:* `secure-login.example`
  - *Information Requested:* `✓ Username`, `✓ Password`
  - *Security Checks:* HTTPS: ✓ | Domain Consistency: ✕ | Redirect: ⚠ | Reputation: ✕ | Credential Request: ✕
  - *Risk:* 🔴 **HIGH**
  - *Why this risk:* “The destination shows suspicious characteristics and requests login credentials.”
  - *Buttons:* `[ Continue Anyway ]` `[ Cancel ]`
- **Interactive Risk Simulator**: Checkbox playground to dynamically simulate threat penalty weights.
- **Custom QR Generator**: Enter any text/URL to render a live scannable QR code on screen.

### 5. 📜 Scan History & Telemetry
- Filterable by **All**, **Low Risk**, **Medium Risk**, and **High Risk**.
- Displays Timestamp, QR Type, Detected Action, Destination, Risk Badge, and User Decision (Continued vs Cancelled).
- **Inspect Action Preview**: Re-opens the Action Preview for any past scan.

### 6. ℹ️ About & Security Ethics
- Explains zero-trust philosophy.
- Details the Core Technologies: *Computer Vision*, *Cybersecurity*, *AI/NLP Intent Engine*, *Web Development*, *API & Microservices*.
- **Ethical Disclaimer**: Explicitly explains that a LOW risk score means no suspicious heuristics were detected, but does not claim 100% invulnerability.

---

## 🏗️ Technical Architecture

```
QR Shield/
├── app.py                   # Flask server, REST API endpoints, static handler
├── analyzer.py              # Modular cybersecurity inspection engine
├── database.py              # SQLite storage for scans, telemetry, and seed data
├── run.bat                  # One-click Windows launch script
├── tests/
│   └── test_qrshield.py     # Unit test suite (6 passing tests)
├── static/
│   ├── css/
│   │   └── style.css        # Cybersecurity glassmorphism design system
│   └── js/
│       ├── app.js           # UI navigation, state management, preview renderer
│       ├── scanner.js       # Camera stream, HUD animations, file dropzone
│       ├── jsqr.min.js      # Pure JavaScript QR code decoder
│       └── qrcode.min.js    # Client-side QR generator for interactive demo testing
└── templates/
    └── index.html           # Single-page dashboard interface
```

### Core Modular Functions in `analyzer.py`
- `decodeQR(content)`: Decodes raw stream or normalized payload string.
- `classifyQRType(content)`: Rule-based categorizer (Payment, Login, Registration, Website, Download, Wi-Fi, Contact, App Link, Unknown) structured for future AI/NLP embedding models.
- `analyzeDestination(content, qr_type)`: Performs multi-vector security assessment across HTTPS, domain integrity, redirect indicators, URL structure, reputation, and sensitive inputs.
- `detectAction(content, qr_type, destination_info)`: Extracts human-readable intent.
- `calculateRisk(security_checks, qr_type, action)`: Computes transparent score (0–30 LOW, 31–60 MEDIUM, 61+ HIGH).
- `generateRiskExplanation(risk_level, factors, action)`: Synthesizes explainable "Why this risk?" description.
- `saveScanHistory(data)`: Persists scan telemetry to SQLite.

---

## 🏆 Hackathon Presentation Checklist

| Feature | Requirement | QR Shield Implementation |
|---|---|---|
| Tagline | *"Scan it. Understand it. Then Act."* | Prominently featured on Hero, Header, and About views |
| Main User Flow | Scan ➔ Decode ➔ Type ➔ Destination ➔ Action ➔ Risk ➔ Preview ➔ Decide | Completed with multi-step animation and zero automatic opening |
| Cybersecurity UI | Dark navy, glassmorphism, cyan accents, low/med/high colors | Hand-crafted custom cyber dashboard CSS |
| Scanner | Camera viewfinder with fallback image upload | Live camera feed with reticle + Drag-and-drop file upload |
| Demo Scenarios | Demo 1 (Low), Demo 2 (Medium), Demo 3 (High) | 1-click test cards + scannable QR images |
| Action Preview | Title, risk badge, action, destination, requested info, checks | Full interactive inspection card with explainability |
| Risk Scoring | Transparent point formula (0–30, 31–60, 61+) | Fully implemented and visualized with live simulator |
| History | Filterable table with user decisions | SQLite database with filters for All, Low, Medium, High |
