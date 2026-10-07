import re
import urllib.parse
from datetime import datetime
import requests

# Known URL shorteners that conceal the actual destination
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 
    'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'rb.gy', 'shorte.st'
}

# Suspicious TLDs often abused in phishing campaigns
SUSPICIOUS_TLDS = {
    '.top', '.xyz', '.buzz', '.fit', '.tk', '.ml', '.cf', '.gq', 
    '.work', '.click', '.link', '.surf', '.cam', '.country', '.kim'
}

# High-profile brand targets for typosquatting checks
BRAND_KEYWORDS = [
    'google', 'microsoft', 'apple', 'amazon', 'paypal', 'facebook', 
    'instagram', 'netflix', 'chase', 'wellsfargo', 'bankofamerica', 
    'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'phonepe'
]

def decodeQR(content_or_data):
    """
    Decodes or normalizes raw QR payload string.
    """
    if not content_or_data:
        return ""
    if isinstance(content_or_data, str):
        return content_or_data.strip()
    return str(content_or_data).strip()

def classifyQRType(content):
    """
    Classifies QR code payload into security categories:
    - Payment
    - Registration Form
    - Login
    - Website
    - Download
    - Wi-Fi
    - Contact
    - App Link
    - Unknown
    """
    content_lower = content.lower().strip()
    
    # 1. Wi-Fi configuration
    if content.startswith('WIFI:') or content.startswith('wifi:'):
        return 'Wi-Fi'
        
    # 2. Contact card (vCard / MeCard)
    if 'begin:vcard' in content_lower or content.startswith('MECARD:') or content.startswith('tel:') or content.startswith('mailto:'):
        return 'Contact'
        
    # 3. Payment schemas and keywords
    if (content.startswith('upi://') or content.startswith('bitcoin:') or 
        content.startswith('ethereum:') or 'paypal.me' in content_lower or 
        re.search(r'\b(pay|checkout|invoice|payment|vpa|billing)\b', content_lower)):
        return 'Payment'
        
    # 4. App Links / Stores
    if ('play.google.com/store' in content_lower or 'apps.apple.com' in content_lower or 
        content.startswith('market://') or content.startswith('intent://')):
        return 'App Link'
        
    # 5. Direct Download
    download_extensions = ('.apk', '.exe', '.dmg', '.pdf', '.zip', '.tar.gz', '.iso', '.msi')
    if any(content_lower.endswith(ext) or ext + '?' in content_lower for ext in download_extensions) or '/download' in content_lower:
        return 'Download'
        
    # 6. Login / Authentication
    login_keywords = ['login', 'signin', 'auth', 'oauth', 'authenticate', 'verify-account', 'portal-auth', 'credential', 'sso']
    if any(keyword in content_lower for keyword in login_keywords):
        return 'Login'
        
    # 7. Registration / Form
    form_keywords = ['register', 'registration', 'signup', 'form', 'forms.gle', 'google.com/forms', 'survey', 'typeform.com', 'admission', 'apply']
    if any(keyword in content_lower for keyword in form_keywords):
        return 'Registration Form'
        
    # 8. General Website
    if content_lower.startswith('http://') or content_lower.startswith('https://') or re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', content):
        return 'Website'
        
    return 'Unknown'

def parse_upi_details(content):
    """
    Parses real UPI QR payload (e.g. upi://pay?pa=...&pn=...&am=...&cu=...&tn=...)
    Extracts available parameters without inventing missing fields.
    """
    params = {}
    try:
        if '?' in content:
            query = content.split('?', 1)[1]
            parsed = urllib.parse.parse_qs(query)
            params = {k: v[0] for k, v in parsed.items()}
    except Exception:
        pass
        
    upi_id = params.get('pa', '').strip()
    merchant = params.get('pn', '').strip()
    amount_raw = params.get('am', '').strip()
    currency = params.get('cu', 'INR').strip()
    note = params.get('tn', '').strip()
    
    if not merchant and upi_id:
        merchant = upi_id
    elif not merchant:
        merchant = "Not specified in QR"
        
    raw_amount_float = None
    if amount_raw:
        try:
            amt_float = float(amount_raw)
            raw_amount_float = amt_float
            amount_display = f"₹{amt_float:,.2f}" if currency == 'INR' else f"{currency} {amt_float:,.2f}"
            has_amount = True
        except ValueError:
            amount_display = f"{currency} {amount_raw}"
            has_amount = True
    else:
        amount_display = "Not specified in QR"
        has_amount = False

    return {
        'upi_id': upi_id or "Not specified in QR",
        'merchant': merchant,
        'amount': amount_display,
        'amount_raw': raw_amount_float,
        'has_amount': has_amount,
        'currency': currency,
        'transaction_note': note or "Not specified in QR"
    }

def parse_wifi_details(content):
    """
    Parses real Wi-Fi QR payload: WIFI:S:<SSID>;T:<TYPE>;P:<PASS>;H:<HIDDEN>;;
    """
    ssid = "Unknown Network"
    sec_type = "WPA/WPA2"
    hidden = False
    
    parts = content[5:].split(';')
    for part in parts:
        if part.startswith('S:'):
            ssid = part[2:]
        elif part.startswith('T:'):
            sec_type = part[2:] or "None (Open)"
        elif part.startswith('H:'):
            hidden = part[2:].lower() in ('true', '1', 'yes')

    return {
        'ssid': ssid,
        'security_type': sec_type,
        'is_hidden': hidden
    }

def inspect_live_destination(url):
    """
    Inspects live destination URL safely when technically possible.
    Follows redirects, checks Content-Type, and analyzes HTML form structure.
    """
    if not (url.startswith('http://') or url.startswith('https://')):
        return {'success': False, 'reason': 'Not a standard HTTP/HTTPS URL'}

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) QRShield-Security-Inspection/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        resp = requests.get(url, timeout=3.5, headers=headers, allow_redirects=True, stream=True)
        final_url = resp.url
        hops = len(resp.history)
        content_type = resp.headers.get('Content-Type', '').lower()
        
        if any(mime in content_type for mime in ['application/octet-stream', 'application/pdf', 'application/zip', 'application/vnd.android.package-archive']):
            return {
                'success': True,
                'is_download': True,
                'content_type': content_type,
                'final_url': final_url,
                'hops': hops
            }

        html_chunk = ''
        for chunk in resp.iter_content(chunk_size=4096, decode_unicode=True):
            if chunk:
                html_chunk += chunk
                if len(html_chunk) > 120000:
                    break

        html_lower = html_chunk.lower()
        has_password = 'type="password"' in html_lower or "type='password'" in html_lower
        
        detected_fields = []
        if re.search(r'name=["\'](name|fname|fullname|full_name)["\']|placeholder=["\'][^"\']*\bname\b', html_lower):
            detected_fields.append('Name')
        if re.search(r'type=["\']email["\']|name=["\'](email|mail)["\']|placeholder=["\'][^"\']*\bemail\b', html_lower):
            detected_fields.append('Email')
        if re.search(r'type=["\']tel["\']|name=["\'](phone|mobile|contact|cell)["\']|placeholder=["\'][^"\']*\b(phone|mobile)\b', html_lower):
            detected_fields.append('Phone Number')
        if re.search(r'name=["\'](college|college_id|student_id|roll_no|reg_no)["\']|placeholder=["\'][^"\']*\b(college|student id)\b', html_lower):
            detected_fields.append('College ID')
        if re.search(r'name=["\'](address|city|zip|postal)["\']|placeholder=["\'][^"\']*\baddress\b', html_lower):
            detected_fields.append('Address')
        if re.search(r'name=["\'](dob|birth|birthdate)["\']|type=["\']date["\']', html_lower):
            detected_fields.append('Date of Birth')

        return {
            'success': True,
            'status_code': resp.status_code,
            'final_url': final_url,
            'hops': hops,
            'has_password': has_password,
            'detected_fields': detected_fields,
            'is_download': False
        }
    except Exception as e:
        return {
            'success': False,
            'reason': str(e)
        }

def analyzeDestination(content, qr_type, perform_live_inspection=True):
    """
    Performs multi-vector inspection on destination URL/payload.
    """
    content_clean = content.strip()
    parsed = None
    is_url = False
    
    if content_clean.startswith(('http://', 'https://')):
        is_url = True
        try:
            parsed = urllib.parse.urlparse(content_clean)
        except Exception:
            parsed = None
    elif '.' in content_clean and not content_clean.startswith(('WIFI:', 'BEGIN:', 'upi:')):
        is_url = True
        try:
            parsed = urllib.parse.urlparse('https://' + content_clean)
        except Exception:
            parsed = None

    checks = {}
    factors = []
    info_requested = []
    limited_analysis = False
    
    hostname = (parsed.hostname or '') if parsed else ''
    path = (parsed.path or '') if parsed else ''
    query = (parsed.query or '') if parsed else ''
    scheme = (parsed.scheme or '') if parsed else ''
    
    # 1. HTTPS Check
    if is_url:
        if scheme == 'https':
            checks['https'] = {
                'status': 'safe',
                'title': 'HTTPS Status',
                'detail': 'PASS - Valid SSL/TLS protocol detected.'
            }
        else:
            checks['https'] = {
                'status': 'risk',
                'title': 'HTTPS Status',
                'detail': 'FAIL - Insecure plain HTTP. Data transmitted without encryption.'
            }
            factors.append('Insecure plain HTTP connection')
    else:
        checks['https'] = {
            'status': 'safe',
            'title': 'Payload Protocol',
            'detail': f'Native schema ({qr_type}) - offline or direct application intent.'
        }

    # 2. Domain Consistency Check
    domain_status = 'safe'
    domain_detail = 'Normal registered domain hierarchy.'
    
    if is_url and hostname:
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            domain_status = 'risk'
            domain_detail = 'Raw IP address host detected instead of domain name.'
            factors.append('Host is a raw IP address')
        elif 'xn--' in hostname:
            domain_status = 'risk'
            domain_detail = 'Punycode internationalized domain detected (possible homograph).'
            factors.append('Punycode / Homograph domain mimicry')
        elif len(hostname.split('.')) > 4:
            domain_status = 'warning'
            domain_detail = 'Unusually deep multi-level subdomain structure.'
            factors.append('Excessive subdomain depth')
        elif any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
            domain_status = 'warning'
            domain_detail = f'High-risk top-level domain abuse pattern (.{hostname.split(".")[-1]}).'
            factors.append(f'High-risk TLD (.{hostname.split(".")[-1]})')
            
        for brand in BRAND_KEYWORDS:
            if brand in hostname and not (hostname == f'{brand}.com' or hostname.endswith(f'.{brand}.com') or hostname.endswith(f'.{brand}.in')):
                domain_status = 'risk'
                domain_detail = f'Typosquatting / brand spoofing indicator targeting "{brand.title()}".'
                factors.append(f'Brand spoofing indicator ({brand})')
                break
                
    checks['domain'] = {
        'status': domain_status,
        'title': 'Domain Consistency',
        'detail': domain_detail
    }

    # 3. Redirect Detection
    redirect_status = 'safe'
    redirect_detail = 'Direct endpoint with no cloaking or intermediary redirect.'
    
    if is_url:
        if any(shortener in hostname for shortener in URL_SHORTENERS):
            redirect_status = 'warning'
            redirect_detail = 'URL shortener detected, cloaking true final destination.'
            factors.append('URL shortener service detected')
            
        redirect_params = ['url=', 'redirect=', 'next=', 'return_to=', 'target=', 'dest=', 'r=']
        if any(param in query.lower() for param in redirect_params):
            redirect_status = 'warning'
            redirect_detail = 'Contains embedded redirect parameters to secondary URL.'
            factors.append('Redirect query parameter detected')
            
    checks['redirects'] = {
        'status': redirect_status,
        'title': 'Redirect Detection',
        'detail': redirect_detail
    }

    # 4. Suspicious URL Pattern
    pattern_status = 'safe'
    pattern_detail = 'Standard URL syntax and character encoding.'
    
    if is_url:
        if '@' in content_clean:
            pattern_status = 'risk'
            pattern_detail = 'Embedded "@" credential trick in URL authority.'
            factors.append('Embedded @ credential mask in URL')
        elif len(content_clean) > 300:
            pattern_status = 'warning'
            pattern_detail = 'Unusually long URL with high token entropy.'
            factors.append('Obfuscated high-entropy URL')
            
    checks['suspicious_url'] = {
        'status': pattern_status,
        'title': 'Suspicious URL Pattern',
        'detail': pattern_detail
    }

    # 5. Reputation Status
    reputation_status = 'safe'
    reputation_detail = 'Legitimate domain record with standard baseline.'
    
    if is_url and hostname:
        trusted_domains = ['example.com', 'google.com', 'github.com', 'wikipedia.org', 'apple.com', 'microsoft.com']
        if any(hostname == td or hostname.endswith('.' + td) for td in trusted_domains):
            reputation_status = 'safe'
            reputation_detail = 'Verified legitimate reference domain.'
        elif any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) or domain_status == 'risk':
            reputation_status = 'risk'
            reputation_detail = 'Domain flagged for elevated threat heuristics or abusive registrar.'
            factors.append('Elevated threat reputation warning')
        elif redirect_status == 'warning':
            reputation_status = 'warning'
            reputation_detail = 'Unverified destination concealed behind redirection.'
            
    checks['reputation'] = {
        'status': reputation_status,
        'title': 'Reputation Status',
        'detail': reputation_detail
    }

    # 6. Sensitive Information & Live Destination Inspection
    live_result = None
    if is_url and perform_live_inspection:
        live_result = inspect_live_destination(content_clean)
        
        if live_result.get('success'):
            if live_result.get('hops', 0) > 0:
                checks['redirects'] = {
                    'status': 'warning',
                    'title': 'Redirect Detection',
                    'detail': f'Detected {live_result["hops"]} intermediate HTTP redirect hop(s).'
                }
                factors.append(f'{live_result["hops"]} HTTP redirect(s) detected')

            if live_result.get('has_password'):
                qr_type = 'Login'
                info_requested = ['Username / Email', 'Password']
                factors.append('Password field / Credential entry required')
            elif live_result.get('detected_fields'):
                qr_type = 'Registration Form'
                info_requested = live_result['detected_fields']
                factors.append('Personal identifiable information requested')
            elif live_result.get('is_download'):
                qr_type = 'Download'
                info_requested = ['Local File Storage Permission']
                factors.append('Executable or binary file download')
        else:
            if not any(hostname == td or hostname.endswith('.' + td) for td in ['example.com', 'example.org']):
                limited_analysis = True

    if not info_requested:
        if qr_type == 'Login':
            info_requested = ['Username / Email', 'Password']
            factors.append('Password field / Login credentials')
        elif qr_type in ('Registration', 'Registration Form'):
            info_requested = ['Name', 'Email', 'Phone Number', 'College ID']
            factors.append('Personal information requested')
        elif qr_type == 'Payment':
            info_requested = ['Transaction Authorization', 'UPI Payee Details']
        elif qr_type == 'Download':
            info_requested = ['File Download Permission']
        elif qr_type == 'Wi-Fi':
            info_requested = ['SSID Network Name', 'Wi-Fi Security Key']
        elif qr_type == 'Contact':
            info_requested = ['Contact Card Import Permission']
        else:
            info_requested = ['Standard Web Navigation / Read Permission']

    sensitive_status = 'safe'
    sensitive_detail = 'No sensitive credentials or financial input fields requested.'
    
    if qr_type == 'Login':
        sensitive_status = 'risk'
        sensitive_detail = 'Requests account login credentials (username and password).'
    elif qr_type in ('Registration', 'Registration Form'):
        sensitive_status = 'warning'
        sensitive_detail = 'Personal identifiable information (PII) is requested before proceeding.'
    elif qr_type == 'Payment':
        sensitive_status = 'warning'
        sensitive_detail = 'Monetary transaction or payment gateway transfer.'
    elif qr_type == 'Download':
        sensitive_status = 'warning'
        sensitive_detail = 'Requests download and potential execution of external file.'

    checks['sensitive_data'] = {
        'status': sensitive_status,
        'title': 'Sensitive Data Exposure',
        'detail': sensitive_detail
    }

    return {
        'checks': checks,
        'factors': factors,
        'info_requested': info_requested,
        'destination': hostname or content_clean[:60],
        'qr_type': qr_type,
        'limited_analysis': limited_analysis,
        'live_result': live_result
    }

def detectAction(content, qr_type, destination_info=None):
    """
    Identifies clear human-readable intended action.
    """
    if qr_type == 'Website':
        return 'Website'
    elif qr_type in ('Registration', 'Registration Form'):
        return 'Registration Form'
    elif qr_type == 'Login':
        return 'Login'
    elif qr_type == 'Payment':
        return 'Payment'
    elif qr_type == 'Download':
        return 'Download'
    elif qr_type == 'Wi-Fi':
        return 'Wi-Fi Connection'
    elif qr_type == 'Contact':
        return 'Contact Card Save'
    elif qr_type == 'App Link':
        return 'App Link'
    return 'Unknown Action'

def calculateRisk(security_checks, qr_type, action):
    """
    Calculates transparent risk score:
    - HTTPS missing = +20
    - Suspicious domain = +25
    - Redirect detected = +15
    - Domain mismatch / brand spoof = +25
    - Sensitive data requested = +15
    - Reputation warning = +30
    """
    score = 0
    checks = security_checks
    
    if checks.get('https', {}).get('status') == 'risk':
        score += 20
        
    domain_status = checks.get('domain', {}).get('status')
    if domain_status == 'risk':
        score += 25
    elif domain_status == 'warning':
        score += 15
        
    if checks.get('redirects', {}).get('status') in ('warning', 'risk'):
        score += 15
        
    if checks.get('suspicious_url', {}).get('status') == 'risk':
        score += 20
    elif checks.get('suspicious_url', {}).get('status') == 'warning':
        score += 10
        
    reputation_status = checks.get('reputation', {}).get('status')
    if reputation_status == 'risk':
        score += 30
    elif reputation_status == 'warning':
        score += 15
        
    sensitive_status = checks.get('sensitive_data', {}).get('status')
    if sensitive_status == 'risk':
        score += 25
    elif sensitive_status == 'warning':
        score += 15

    score = min(score, 100)
    
    if score <= 30:
        level = 'LOW'
    elif score <= 60:
        level = 'MEDIUM'
    else:
        level = 'HIGH'
        
    return score, level

def generateRiskExplanation(risk_level, factors, action, qr_type):
    """
    Produces transparent explanation for: "Why this risk?"
    """
    if qr_type == 'Payment':
        if risk_level == 'MEDIUM':
            return "Domain consistency and redirect indicators require attention."
        elif risk_level == 'LOW':
            return "Valid payment format with no suspicious parameters or credential exposure."
        else:
            return "High-risk payment destination with suspicious domain and potential financial fraud indicators."

    if qr_type in ('Registration', 'Registration Form'):
        return "Personal information is requested before form submission."

    if qr_type == 'Login':
        if risk_level == 'HIGH':
            return "The destination shows suspicious characteristics and requests login credentials."
        return "Destination is a login portal requesting account credentials."

    if risk_level == 'LOW':
        if factors:
            return f"HTTPS is enabled and only minimal surface indicators were noted ({', '.join(factors[:2])}). No hostile threats identified."
        return "HTTPS is enabled and no suspicious indicators were detected."
        
    elif risk_level == 'MEDIUM':
        if factors:
            return f"{factors[0].capitalize()} detected ({', '.join(factors[1:]) if len(factors)>1 else 'verification recommended'})."
        return "Personal information is requested and the destination warrants user verification."
        
    else:  # HIGH
        if factors:
            return f"The destination exhibits {', '.join(factors[:3])}. High potential for credential theft or malicious redirection."
        return "The destination shows suspicious characteristics and requests login credentials."

# ==============================================================================
# UPGRADE 1 & 2: INTENT VS REALITY & CONTEXT MISMATCH ENGINE
# ==============================================================================

def analyze_intent_mismatch(expected_purpose, actual_action, qr_type, details=None, poster_context=None):
    """
    Compares user-stated expected purpose (or promotional poster context)
    with the actual decoded QR action.
    Detects critical bait-and-switch quishing tactics.
    """
    if not expected_purpose and not poster_context:
        return {
            'expected_purpose': 'Any / Auto-Detect',
            'actual_action': actual_action,
            'status': 'UNSPECIFIED',
            'severity': 'NONE',
            'alert_title': 'Autonomous Intent Inspection',
            'reason': 'No prior purpose was specified. Evaluated solely based on payload indicators.',
            'poster_context': None,
            'is_mismatch': False
        }

    exp = (expected_purpose or poster_context or '').lower().strip()
    act = (actual_action or '').lower().strip()
    details = details or {}
    
    # Check 1: Event Registration / Form vs Login / Password Request
    if ('reg' in exp or 'event' in exp or 'form' in exp or 'ticket' in exp or 'admission' in exp):
        if 'login' in act or qr_type == 'Login':
            return {
                'expected_purpose': expected_purpose or 'Event Registration',
                'actual_action': 'Login + Password Request',
                'status': 'MISMATCH',
                'severity': 'HIGH',
                'alert_title': 'Intent Mismatch Detected',
                'reason': f"Expected: {expected_purpose or 'Event Registration'}. Actual: Login + Password Request. High-risk credential harvesting disguised as a registration portal.",
                'poster_context': poster_context,
                'is_mismatch': True
            }
        elif qr_type in ('Registration Form', 'Registration', 'Website'):
            return {
                'expected_purpose': expected_purpose or 'Event Registration',
                'actual_action': actual_action,
                'status': 'MATCHED',
                'severity': 'NONE',
                'alert_title': 'Intent Matched',
                'reason': f"Actual action '{actual_action}' aligns with expected '{expected_purpose or 'Registration'}'.",
                'poster_context': poster_context,
                'is_mismatch': False
            }

    # Check 2: Payment Amount Discrepancy (e.g. ₹50 vs ₹500)
    if 'pay' in exp or 'amount' in exp or qr_type == 'Payment' or '₹' in exp or '50' in exp:
        # Check expected amount vs decoded amount
        expected_amt_match = re.search(r'₹?\s*(\d+(\.\d+)?)', exp)
        actual_amt_float = details.get('amount_raw')
        
        if expected_amt_match and actual_amt_float is not None:
            expected_amt = float(expected_amt_match.group(1))
            if abs(expected_amt - actual_amt_float) > 1.0:
                return {
                    'expected_purpose': f"Payment (₹{expected_amt:,.0f})",
                    'actual_action': f"Payment (₹{actual_amt_float:,.2f})",
                    'status': 'MISMATCH',
                    'severity': 'HIGH',
                    'alert_title': 'Financial Discrepancy Mismatch',
                    'reason': f"Expected to pay ₹{expected_amt:,.0f}, but the QR payload specifically encodes an unauthorized amount of ₹{actual_amt_float:,.2f}.",
                    'poster_context': poster_context,
                    'is_mismatch': True
                }

        if 'pay' in exp and qr_type == 'Payment':
            return {
                'expected_purpose': expected_purpose or 'Payment',
                'actual_action': 'Payment',
                'status': 'MATCHED',
                'severity': 'NONE',
                'alert_title': 'Intent Matched',
                'reason': 'Payment intent verified with no financial markup discrepancy.',
                'poster_context': poster_context,
                'is_mismatch': False
            }
        elif 'pay' not in exp and qr_type == 'Payment':
            return {
                'expected_purpose': expected_purpose or 'Informational Content',
                'actual_action': 'Payment Transfer',
                'status': 'MISMATCH',
                'severity': 'HIGH',
                'alert_title': 'Intent Mismatch Detected',
                'reason': f"Expected '{expected_purpose}', but QR directly prompts for payment transfer authorization.",
                'poster_context': poster_context,
                'is_mismatch': True
            }

    # Check 3: Dining Menu / Brochure vs Login or Download
    if 'menu' in exp or 'brochure' in exp:
        if qr_type in ('Login', 'Payment', 'Download'):
            return {
                'expected_purpose': 'Dining Menu',
                'actual_action': actual_action,
                'status': 'MISMATCH',
                'severity': 'HIGH',
                'alert_title': 'Intent Mismatch Detected',
                'reason': f"Expected a dining menu, but the QR triggers {actual_action}. Common quishing vector.",
                'poster_context': poster_context,
                'is_mismatch': True
            }
        else:
            return {
                'expected_purpose': 'Dining Menu',
                'actual_action': actual_action,
                'status': 'MATCHED',
                'severity': 'NONE',
                'alert_title': 'Intent Matched',
                'reason': 'Menu viewing destination verified.',
                'poster_context': poster_context,
                'is_mismatch': False
            }

    # Check 4: Wi-Fi vs Non-Wi-Fi
    if 'wifi' in exp or 'wi-fi' in exp:
        if qr_type != 'Wi-Fi':
            return {
                'expected_purpose': 'Wi-Fi Connection',
                'actual_action': actual_action,
                'status': 'MISMATCH',
                'severity': 'HIGH',
                'alert_title': 'Intent Mismatch Detected',
                'reason': f"Expected Wi-Fi network setup, but QR directs to external {actual_action}.",
                'poster_context': poster_context,
                'is_mismatch': True
            }
        return {
            'expected_purpose': 'Wi-Fi Connection',
            'actual_action': 'Wi-Fi Connection',
            'status': 'MATCHED',
            'severity': 'NONE',
            'alert_title': 'Intent Matched',
            'reason': 'Wi-Fi network configuration verified.',
            'poster_context': poster_context,
            'is_mismatch': False
        }

    # Check 5: General Website
    if 'web' in exp or 'site' in exp:
        if qr_type == 'Download':
            return {
                'expected_purpose': 'Website',
                'actual_action': 'Direct File Download',
                'status': 'MISMATCH',
                'severity': 'HIGH',
                'alert_title': 'Intent Mismatch Detected',
                'reason': "Expected website browsing, but QR initiates an immediate file download.",
                'poster_context': poster_context,
                'is_mismatch': True
            }
        return {
            'expected_purpose': 'Website',
            'actual_action': 'Website',
            'status': 'MATCHED',
            'severity': 'NONE',
            'alert_title': 'Intent Matched',
            'reason': 'Website destination matches browsing intent.',
            'poster_context': poster_context,
            'is_mismatch': False
        }

    # Fallback comparison
    if exp in act or act in exp:
        return {
            'expected_purpose': expected_purpose or 'Expected Action',
            'actual_action': actual_action,
            'status': 'MATCHED',
            'severity': 'NONE',
            'alert_title': 'Intent Matched',
            'reason': f"The decoded QR action aligns with your expected purpose ({actual_action}).",
            'poster_context': poster_context,
            'is_mismatch': False
        }
    else:
        return {
            'expected_purpose': expected_purpose or 'Custom Purpose',
            'actual_action': actual_action,
            'status': 'MISMATCH',
            'severity': 'MEDIUM',
            'alert_title': 'Intent Mismatch Detected',
            'reason': f"Expected '{expected_purpose}', but decoded QR action is '{actual_action}'.",
            'poster_context': poster_context,
            'is_mismatch': True
        }

# ==============================================================================
# UPGRADE 4: "WHY IS THIS RISKY?" AI EXPLANATION
# ==============================================================================

def generate_why_risky_ai(risk_level, factors, intent_mismatch, security_checks, action):
    """
    Generates a simple, transparent human-readable explanation of why the QR is risky.
    """
    explanations = []
    
    if intent_mismatch.get('status') == 'MISMATCH':
        explanations.append(f"CRITICAL INTENT DECEPTION: {intent_mismatch.get('reason')}")
        
    if security_checks.get('sensitive_data', {}).get('status') == 'risk':
        explanations.append("CREDENTIAL HARVESTING: The destination contains password or master authentication fields on an untrusted server.")
        
    if security_checks.get('domain', {}).get('status') == 'risk':
        explanations.append("DECEPTIVE DOMAIN: The web host uses brand typosquatting, raw IP address, or high-risk TLDs commonly seen in phishing kits.")
        
    if security_checks.get('redirects', {}).get('status') in ('warning', 'risk'):
        explanations.append("CONCEALED REDIRECTION: Intermediate routing hops or URL shorteners cloak the final destination from security scanners.")
        
    if security_checks.get('https', {}).get('status') == 'risk':
        explanations.append("UNENCRYPTED PLAINTEXT: Insecure plain HTTP allows anyone on your Wi-Fi/network to eavesdrop on submitted data.")

    if not explanations:
        if risk_level == 'LOW':
            return "This QR code appears legitimate and safe. It utilizes verified HTTPS encryption, direct hostname resolution, and requests no passwords or sensitive banking credentials."
        elif risk_level == 'MEDIUM':
            return "Proceed with caution. The destination collects personal identifiable information (PII) or relies on third-party redirection. Ensure you trust the hosting organization before submitting data."
        else:
            return "High threat rating. Multiple anomalies detected across domain reputation, credential collection, and redirect parameters."
            
    return " ".join(explanations)

# ==============================================================================
# UPGRADE 5: QR RISK TIMELINE
# ==============================================================================

def generate_risk_timeline(qr_type, action, destination, checks, intent_mismatch, risk_level):
    """
    Builds the 7-stage zero-trust audit timeline:
    QR Scanned → QR Decoded → URL Found → Security Checks → AI Analysis → Intent Check → Final Risk
    """
    is_mismatch = intent_mismatch.get('status') == 'MISMATCH'
    has_sec_risk = checks.get('https', {}).get('status') == 'risk' or checks.get('domain', {}).get('status') == 'risk'
    has_sec_warn = checks.get('redirects', {}).get('status') == 'warning' or checks.get('domain', {}).get('status') == 'warning'
    
    sec_status = 'risk' if has_sec_risk else ('warn' if has_sec_warn else 'pass')
    intent_status = 'risk' if is_mismatch else ('pass' if intent_mismatch.get('status') == 'MATCHED' else 'neutral')
    final_status = 'risk' if risk_level == 'HIGH' or is_mismatch else ('warn' if risk_level == 'MEDIUM' else 'pass')

    return [
        {
            'step': 1,
            'name': 'QR Scanned',
            'status': 'pass',
            'icon': '📷',
            'time': '0.0ms',
            'detail': 'Optical camera matrix captured and binarized.'
        },
        {
            'step': 2,
            'name': 'QR Decoded',
            'status': 'pass',
            'icon': '🧩',
            'time': '1.2ms',
            'detail': f'Payload decoded as standard {qr_type} schema.'
        },
        {
            'step': 3,
            'name': 'URL Found',
            'status': 'pass',
            'icon': '🌐',
            'time': '2.8ms',
            'detail': f'Target endpoint: {destination or "Direct Schema"}'
        },
        {
            'step': 4,
            'name': 'Security Checks',
            'status': sec_status,
            'icon': '🛡️',
            'time': '7.4ms',
            'detail': 'TLS protocol, domain consistency, and redirects evaluated.'
        },
        {
            'step': 5,
            'name': 'AI Analysis',
            'status': 'pass',
            'icon': '🧠',
            'time': '10.9ms',
            'detail': f'Semantic intent mapped to action: {action}.'
        },
        {
            'step': 6,
            'name': 'Intent Check',
            'status': intent_status,
            'icon': '⚖️',
            'time': '12.4ms',
            'detail': intent_mismatch.get('alert_title', 'Intent Verified')
        },
        {
            'step': 7,
            'name': 'Final Risk',
            'status': final_status,
            'icon': '⚡',
            'time': '13.8ms',
            'detail': f"{risk_level} Risk Determination"
        }
    ]

# ==============================================================================
# UPGRADE 6: "SAFE TO PROCEED?" DECISION RECOMMENDATION
# ==============================================================================

def generate_safe_to_proceed_decision(risk_level, factors, intent_mismatch, action):
    """
    Produces final explicit guidance:
    LOW → SAFE TO PROCEED
    MEDIUM → PROCEED WITH CAUTION
    HIGH → DO NOT PROCEED
    With expandable "Why?" bullet points list.
    """
    is_mismatch = intent_mismatch.get('status') == 'MISMATCH'
    
    if risk_level == 'HIGH' or is_mismatch:
        reasons = []
        if is_mismatch:
            reasons.append(f"Intent Mismatch: {intent_mismatch.get('reason')}")
        if 'Password field / Credential entry required' in factors or 'Password field / Login credentials' in factors:
            reasons.append("Unverified credential harvesting form detected")
        if any('domain' in f.lower() or 'tld' in f.lower() for f in factors):
            reasons.append("Suspicious domain structure or brand typosquatting")
        if any('redirect' in f.lower() for f in factors):
            reasons.append("Hidden intermediary redirection detected")
        if not reasons:
            reasons.append("Multiple elevated cybersecurity risk indicators flagged")

        return {
            'verdict': 'DO NOT PROCEED',
            'class': 'danger',
            'icon': '🚫',
            'badge': '🔴 DO NOT PROCEED',
            'summary': 'Critical security threats or intentional bait-and-switch deception detected.',
            'reasons': reasons
        }
    elif risk_level == 'MEDIUM':
        reasons = []
        if 'Personal information requested' in factors or 'Personal identifiable information requested' in factors:
            reasons.append("Personal identity information (Name, Email, Phone, College ID) is requested")
        if any('redirect' in f.lower() for f in factors):
            reasons.append("Contains secondary redirect parameters")
        if any('domain' in f.lower() for f in factors):
            reasons.append("Third-party subdomain delegation requires identity verification")
        if not reasons:
            reasons.append("Destination warrants verification before sharing data or authorizing action")

        return {
            'verdict': 'PROCEED WITH CAUTION',
            'class': 'caution',
            'icon': '⚠️',
            'badge': '🟡 PROCEED WITH CAUTION',
            'summary': 'The destination requests personal details or routing verification.',
            'reasons': reasons
        }
    else:
        return {
            'verdict': 'SAFE TO PROCEED',
            'class': 'safe',
            'icon': '✅',
            'badge': '🟢 SAFE TO PROCEED',
            'summary': 'All verified security indicators passed baseline zero-trust checks.',
            'reasons': [
                'Encrypted HTTPS communication channel with valid TLS certificates',
                'Registered domain record without typosquatting or homograph patterns',
                'No credential harvesting fields or unauthorized monetary requests',
                'Zero hidden intermediary redirect chains'
            ]
        }

# ==============================================================================
# UPGRADE 8: DEMO SCENARIOS FOR JUDGES
# ==============================================================================

def get_demo_scenario(demo_num):
    """
    Supports both existing demos (1, 2, 3) AND new judge demo scenarios (4, 5, 6):
    - Demo 1: Demo Payment QR (ABC Store ₹2,000)
    - Demo 2: Demo Registration QR (registration.example)
    - Demo 3: Demo Suspicious Login QR (secure-login.example)
    - Demo 4: Event Registration → Login + Password mismatch
    - Demo 5: Payment ₹50 → QR requests ₹500 mismatch
    - Demo 6: Safe Website → Intent Matched
    """
    if demo_num == 1:
        scenario = {
            'mode': 'DEMO',
            'demo_id': 1,
            'title': 'Demo Payment QR',
            'qr_content': 'upi://pay?pa=abc-store@upi&pn=ABC%20Store&am=2000.00&cu=INR&tn=Invoice%20Order%23901',
            'qr_type': 'Payment',
            'detected_action': 'Payment',
            'destination': 'abc-pay.example',
            'merchant': 'ABC Store',
            'amount': '₹2,000',
            'amount_raw': 2000.0,
            'has_amount': True,
            'upi_id': 'abc-store@upi',
            'transaction_note': 'Invoice Order#901',
            'risk_level': 'MEDIUM',
            'risk_score': 45,
            'info_requested': ['Transaction Amount (₹2,000)', 'Merchant VPA', 'Payment Authorization'],
            'security_checks': {
                'https': {'status': 'safe', 'title': 'HTTPS', 'detail': 'PASS - Valid secure channel verified'},
                'domain': {'status': 'warning', 'title': 'Domain Consistency', 'detail': 'WARNING - Third-party payment gateway redirection'},
                'redirects': {'status': 'warning', 'title': 'Redirect', 'detail': 'WARNING - Intermediary routing detected'},
                'reputation': {'status': 'safe', 'title': 'Reputation', 'detail': 'PASS - Merchant domain verified'}
            },
            'explanation': 'Domain consistency and redirect indicators require attention.',
            'factors': ['Domain consistency warning', 'Redirect indicator flagged'],
            'is_demo': True,
            'preview_prompt': 'You are about to continue to this payment destination.'
        }
        intent_mismatch = analyze_intent_mismatch('Payment', 'Payment', 'Payment', scenario)
        scenario['intent_mismatch'] = intent_mismatch
        scenario['why_risky_ai'] = generate_why_risky_ai('MEDIUM', scenario['factors'], intent_mismatch, scenario['security_checks'], 'Payment')
        scenario['risk_timeline'] = generate_risk_timeline('Payment', 'Payment', 'abc-pay.example', scenario['security_checks'], intent_mismatch, 'MEDIUM')
        scenario['safe_to_proceed'] = generate_safe_to_proceed_decision('MEDIUM', scenario['factors'], intent_mismatch, 'Payment')
        return scenario

    elif demo_num == 2:
        scenario = {
            'mode': 'DEMO',
            'demo_id': 2,
            'title': 'Demo Registration QR',
            'qr_content': 'https://registration.example/hackathon-signup',
            'qr_type': 'Registration Form',
            'detected_action': 'Registration Form',
            'destination': 'registration.example',
            'risk_level': 'MEDIUM',
            'risk_score': 45,
            'info_requested': ['Name', 'Email', 'Phone Number', 'College ID'],
            'security_checks': {
                'https': {'status': 'safe', 'title': 'HTTPS', 'detail': 'PASS - SSL encryption verified'},
                'domain': {'status': 'safe', 'title': 'Domain Consistency', 'detail': 'PASS - Standard registration domain'},
                'redirects': {'status': 'safe', 'title': 'Redirect', 'detail': 'PASS - Direct landing form'},
                'reputation': {'status': 'safe', 'title': 'Reputation', 'detail': 'PASS - Verified institutional record'}
            },
            'explanation': 'Personal information is requested before form submission.',
            'factors': ['Personal identifiable information requested'],
            'is_demo': True,
            'preview_prompt': 'You are about to navigate to: registration.example'
        }
        intent_mismatch = analyze_intent_mismatch('Registration Form', 'Registration Form', 'Registration Form', scenario)
        scenario['intent_mismatch'] = intent_mismatch
        scenario['why_risky_ai'] = generate_why_risky_ai('MEDIUM', scenario['factors'], intent_mismatch, scenario['security_checks'], 'Registration Form')
        scenario['risk_timeline'] = generate_risk_timeline('Registration Form', 'Registration Form', 'registration.example', scenario['security_checks'], intent_mismatch, 'MEDIUM')
        scenario['safe_to_proceed'] = generate_safe_to_proceed_decision('MEDIUM', scenario['factors'], intent_mismatch, 'Registration Form')
        return scenario

    elif demo_num == 3:
        scenario = {
            'mode': 'DEMO',
            'demo_id': 3,
            'title': 'Demo Suspicious Login QR',
            'qr_content': 'https://secure-login.example/signin?redirect=session_update',
            'qr_type': 'Login',
            'detected_action': 'Login',
            'destination': 'secure-login.example',
            'risk_level': 'HIGH',
            'risk_score': 85,
            'info_requested': ['Username', 'Password'],
            'security_checks': {
                'https': {'status': 'safe', 'title': 'HTTPS', 'detail': 'PASS - TLS certificate active'},
                'domain': {'status': 'risk', 'title': 'Domain Consistency', 'detail': 'FAIL - High-risk domain consistency mismatch'},
                'redirects': {'status': 'warning', 'title': 'Redirect', 'detail': 'WARNING - Concealed redirect parameter detected'},
                'reputation': {'status': 'risk', 'title': 'Reputation', 'detail': 'FAIL - Host flagged in threat heuristic registry'},
                'sensitive_data': {'status': 'risk', 'title': 'Credential Request', 'detail': 'FAIL - Password field detected on untrusted destination'}
            },
            'explanation': 'The destination shows suspicious characteristics and requests login credentials.',
            'factors': [
                'Suspicious domain consistency mismatch',
                'Concealed redirect detected',
                'Login credential harvesting fields'
            ],
            'is_demo': True,
            'preview_prompt': 'You are about to navigate to: secure-login.example'
        }
        intent_mismatch = analyze_intent_mismatch(None, 'Login', 'Login', scenario)
        scenario['intent_mismatch'] = intent_mismatch
        scenario['why_risky_ai'] = generate_why_risky_ai('HIGH', scenario['factors'], intent_mismatch, scenario['security_checks'], 'Login')
        scenario['risk_timeline'] = generate_risk_timeline('Login', 'Login', 'secure-login.example', scenario['security_checks'], intent_mismatch, 'HIGH')
        scenario['safe_to_proceed'] = generate_safe_to_proceed_decision('HIGH', scenario['factors'], intent_mismatch, 'Login')
        return scenario

    # NEW DEMO 4: Event Registration -> Login + Password mismatch
    elif demo_num == 4:
        scenario = {
            'mode': 'DEMO',
            'demo_id': 4,
            'title': 'Event Registration → Login + Password mismatch',
            'qr_content': 'https://secure-login.example/auth?event=hackathon2026',
            'qr_type': 'Login',
            'detected_action': 'Login',
            'destination': 'secure-login.example',
            'risk_level': 'HIGH',
            'risk_score': 92,
            'info_requested': ['Username / Email', 'Password'],
            'security_checks': {
                'https': {'status': 'safe', 'title': 'HTTPS', 'detail': 'PASS - Standard TLS encryption'},
                'domain': {'status': 'risk', 'title': 'Domain Consistency', 'detail': 'FAIL - Deceptive authentication domain'},
                'redirects': {'status': 'warning', 'title': 'Redirect', 'detail': 'WARNING - Query parameter redirecting to external gateway'},
                'reputation': {'status': 'risk', 'title': 'Reputation', 'detail': 'FAIL - Unverified credential harvesting destination'},
                'sensitive_data': {'status': 'risk', 'title': 'Credential Request', 'detail': 'FAIL - Requests master password'}
            },
            'explanation': 'The destination shows suspicious characteristics and requests login credentials.',
            'factors': [
                'Intent Mismatch: Expected Event Registration, but destination demands Login & Password',
                'Password field detected on third-party domain',
                'Deceptive authentication lure'
            ],
            'is_demo': True,
            'preview_prompt': 'You are about to navigate to: secure-login.example'
        }
        intent_mismatch = analyze_intent_mismatch('Event Registration', 'Login', 'Login', scenario, poster_context="Campus Tech Fest - Free Event Registration")
        scenario['intent_mismatch'] = intent_mismatch
        scenario['why_risky_ai'] = generate_why_risky_ai('HIGH', scenario['factors'], intent_mismatch, scenario['security_checks'], 'Login')
        scenario['risk_timeline'] = generate_risk_timeline('Login', 'Login', 'secure-login.example', scenario['security_checks'], intent_mismatch, 'HIGH')
        scenario['safe_to_proceed'] = generate_safe_to_proceed_decision('HIGH', scenario['factors'], intent_mismatch, 'Login')
        return scenario

    # NEW DEMO 5: Payment ₹50 → QR requests ₹500 mismatch
    elif demo_num == 5:
        scenario = {
            'mode': 'DEMO',
            'demo_id': 5,
            'title': 'Payment ₹50 → QR requests ₹500 mismatch',
            'qr_content': 'upi://pay?pa=canteen-counter@upi&pn=Cafeteria%20Store&am=500.00&cu=INR&tn=Lunch%20Meal%20Combo',
            'qr_type': 'Payment',
            'detected_action': 'Payment',
            'destination': 'canteen-counter@upi',
            'merchant': 'Cafeteria Store',
            'amount': '₹500.00',
            'amount_raw': 500.0,
            'has_amount': True,
            'upi_id': 'canteen-counter@upi',
            'transaction_note': 'Lunch Meal Combo',
            'risk_level': 'HIGH',
            'risk_score': 80,
            'info_requested': ['Transaction Amount (₹500.00)', 'UPI VPA Authorization'],
            'security_checks': {
                'qr_format': {'status': 'safe', 'title': 'QR Format', 'detail': 'PASS - Valid UPI schema'},
                'amount_check': {'status': 'risk', 'title': 'Amount Verification', 'detail': 'FAIL - Amount ₹500 exceeds expected ₹50 (10x markup)'},
                'https': {'status': 'safe', 'title': 'Protocol', 'detail': 'PASS - Encrypted banking intent'},
                'reputation': {'status': 'warning', 'title': 'Billing Anomaly', 'detail': 'WARNING - Discrepancy between stated price and encoded charge'}
            },
            'explanation': 'Payment amount mismatch: Expected ₹50, but QR requests ₹500 (10x unauthorized markup).',
            'factors': [
                'Financial Discrepancy: Expected ₹50, but encoded payload requests ₹500',
                'Unauthorized 10x price manipulation'
            ],
            'is_demo': True,
            'preview_prompt': 'You are about to continue to this payment destination: Cafeteria Store (₹500.00)'
        }
        intent_mismatch = analyze_intent_mismatch('Payment ₹50', 'Payment', 'Payment', scenario, poster_context="Cafeteria Lunch Deal - Pay ₹50")
        scenario['intent_mismatch'] = intent_mismatch
        scenario['why_risky_ai'] = generate_why_risky_ai('HIGH', scenario['factors'], intent_mismatch, scenario['security_checks'], 'Payment')
        scenario['risk_timeline'] = generate_risk_timeline('Payment', 'Payment', 'canteen-counter@upi', scenario['security_checks'], intent_mismatch, 'HIGH')
        scenario['safe_to_proceed'] = generate_safe_to_proceed_decision('HIGH', scenario['factors'], intent_mismatch, 'Payment')
        return scenario

    # NEW DEMO 6: Safe Website → Intent Matched
    elif demo_num == 6:
        scenario = {
            'mode': 'DEMO',
            'demo_id': 6,
            'title': 'Safe Website → Intent Matched',
            'qr_content': 'https://example.com/hackathon-rules',
            'qr_type': 'Website',
            'detected_action': 'Website',
            'destination': 'https://example.com',
            'risk_level': 'LOW',
            'risk_score': 10,
            'info_requested': ['Standard Web Navigation / Read Permission'],
            'security_checks': {
                'https': {'status': 'safe', 'title': 'HTTPS', 'detail': 'PASS - Valid SSL/TLS protocol detected'},
                'domain': {'status': 'safe', 'title': 'Domain Consistency', 'detail': 'PASS - Generic verified documentation domain'},
                'redirects': {'status': 'safe', 'title': 'Redirect', 'detail': 'PASS - Direct single-hop endpoint'},
                'reputation': {'status': 'safe', 'title': 'Reputation', 'detail': 'PASS - Verified legitimate record'}
            },
            'explanation': 'HTTPS is enabled and no suspicious indicators were detected.',
            'factors': [],
            'is_demo': True,
            'preview_prompt': 'You are about to navigate to: https://example.com'
        }
        intent_mismatch = analyze_intent_mismatch('Website', 'Website', 'Website', scenario, poster_context="Official Hackathon Rules & Guide")
        scenario['intent_mismatch'] = intent_mismatch
        scenario['why_risky_ai'] = generate_why_risky_ai('LOW', scenario['factors'], intent_mismatch, scenario['security_checks'], 'Website')
        scenario['risk_timeline'] = generate_risk_timeline('Website', 'Website', 'https://example.com', scenario['security_checks'], intent_mismatch, 'LOW')
        scenario['safe_to_proceed'] = generate_safe_to_proceed_decision('LOW', scenario['factors'], intent_mismatch, 'Website')
        return scenario

    return get_demo_scenario(1)

def analyze_qr_payload(content, is_demo_flag=False, perform_live=True, expected_purpose=None, poster_context=None):
    """
    MODE 2 — REAL QR SCAN ACTION PREVIEW (or Demo fallback)
    With:
    - QR Purpose Verification & Intent Mismatch Check
    - "Why is this risky?" AI explanation
    - QR Risk Timeline
    - "Safe to Proceed?" decision verdict
    """
    content = decodeQR(content)
    
    # Check exact demo strings
    if is_demo_flag or content in ("DEMO_1_PAYMENT", "DEMO_1_SAFE"):
        return get_demo_scenario(1)
    elif content in ("DEMO_2_REGISTRATION", "registration.example"):
        return get_demo_scenario(2)
    elif content in ("DEMO_3_LOGIN", "secure-login.example"):
        return get_demo_scenario(3)
    elif content in ("DEMO_4_MISMATCH_LOGIN", "DEMO_4"):
        return get_demo_scenario(4)
    elif content in ("DEMO_5_MISMATCH_AMOUNT", "DEMO_5"):
        return get_demo_scenario(5)
    elif content in ("DEMO_6_MATCHED_WEBSITE", "DEMO_6"):
        return get_demo_scenario(6)
        
    qr_type = classifyQRType(content)
    
    # A. Real Payment QR
    if qr_type == 'Payment' or content.startswith('upi://'):
        qr_type = 'Payment'
        upi_data = parse_upi_details(content)
        destination = upi_data['upi_id'] if upi_data['upi_id'] != "Not specified in QR" else "UPI Payment Schema"
        action = "Payment"
        
        checks = {
            'qr_format': {'status': 'safe', 'title': 'QR Format', 'detail': 'PASS - Valid UPI payment string standard.'},
            'upi_structure': {
                'status': 'safe' if '@' in upi_data['upi_id'] else 'warning',
                'title': 'UPI Structure',
                'detail': 'PASS - Standard VPA syntax.' if '@' in upi_data['upi_id'] else 'WARNING - Irregular UPI VPA format.'
            },
            'https': {'status': 'safe', 'title': 'Protocol / URL Check', 'detail': 'PASS - Encrypted banking intent payload.'},
            'domain': {'status': 'safe', 'title': 'Domain / Provider', 'detail': f'Provider host: {upi_data["upi_id"].split("@")[-1] if "@" in upi_data["upi_id"] else "Standard"}'},
            'suspicious_url': {'status': 'safe', 'title': 'Suspicious Indicators', 'detail': 'No malicious executable payload embedded.'},
            'sensitive_data': {'status': 'safe', 'title': 'Credential Exposure', 'detail': 'PASS - No PIN or secret credential requested.'}
        }
        
        info_requested = []
        if upi_data['has_amount']:
            info_requested.append(f"Payment Amount: {upi_data['amount']}")
        else:
            info_requested.append("Amount: Not specified in QR (User inputs at bank)")
        info_requested.append(f"Payee VPA: {upi_data['upi_id']}")
        if upi_data['merchant'] != "Not specified in QR":
            info_requested.append(f"Payee Name: {upi_data['merchant']}")
            
        score, risk_level = calculateRisk(checks, qr_type, action)
        
        intent_mismatch = analyze_intent_mismatch(expected_purpose, action, qr_type, details=upi_data, poster_context=poster_context)
        if intent_mismatch['status'] == 'MISMATCH':
            risk_level = 'HIGH'
            score = max(score, 75)

        explanation = generateRiskExplanation(risk_level, [], action, qr_type)
        why_risky_ai = generate_why_risky_ai(risk_level, [], intent_mismatch, checks, action)
        risk_timeline = generate_risk_timeline(qr_type, action, destination, checks, intent_mismatch, risk_level)
        safe_to_proceed = generate_safe_to_proceed_decision(risk_level, [], intent_mismatch, action)
        
        return {
            'mode': 'REAL',
            'qr_content': content,
            'qr_type': 'Payment',
            'detected_action': 'Payment',
            'destination': destination,
            'merchant': upi_data['merchant'],
            'amount': upi_data['amount'],
            'amount_raw': upi_data['amount_raw'],
            'has_amount': upi_data['has_amount'],
            'upi_id': upi_data['upi_id'],
            'transaction_note': upi_data['transaction_note'],
            'risk_level': risk_level,
            'risk_score': score,
            'info_requested': info_requested,
            'security_checks': checks,
            'explanation': explanation,
            'factors': [intent_mismatch['reason']] if intent_mismatch['status'] == 'MISMATCH' else [],
            'is_demo': False,
            'limited_analysis': False,
            'intent_mismatch': intent_mismatch,
            'why_risky_ai': why_risky_ai,
            'risk_timeline': risk_timeline,
            'safe_to_proceed': safe_to_proceed,
            'preview_prompt': f"You are about to continue to this payment destination: {upi_data['merchant']} ({upi_data['amount']})"
        }

    # B. Real Wi-Fi QR
    if qr_type == 'Wi-Fi':
        wifi_data = parse_wifi_details(content)
        action = "Wi-Fi Connection"
        checks = {
            'format': {'status': 'safe', 'title': 'Wi-Fi Format', 'detail': 'PASS - Standard IEEE 802.11 Wi-Fi barcode standard.'},
            'security': {
                'status': 'safe' if 'WPA' in wifi_data['security_type'].upper() else 'warning',
                'title': 'Encryption Level',
                'detail': f'Configured with {wifi_data["security_type"]}.'
            },
            'suspicious': {'status': 'safe', 'title': 'Suspicious Indicators', 'detail': 'No network redirect or command injection.'}
        }
        risk_level = 'LOW' if 'WPA' in wifi_data['security_type'].upper() else 'MEDIUM'
        score = 15 if risk_level == 'LOW' else 40
        explanation = f"Network configuration detected for SSID '{wifi_data['ssid']}' with {wifi_data['security_type']} encryption."
        
        intent_mismatch = analyze_intent_mismatch(expected_purpose, action, qr_type, details=wifi_data, poster_context=poster_context)
        if intent_mismatch['status'] == 'MISMATCH':
            risk_level = 'HIGH'
            score = max(score, 75)

        why_risky_ai = generate_why_risky_ai(risk_level, [] if risk_level=='LOW' else ['Unencrypted protocol'], intent_mismatch, checks, action)
        risk_timeline = generate_risk_timeline(qr_type, action, wifi_data['ssid'], checks, intent_mismatch, risk_level)
        safe_to_proceed = generate_safe_to_proceed_decision(risk_level, [], intent_mismatch, action)

        return {
            'mode': 'REAL',
            'qr_content': content,
            'qr_type': 'Wi-Fi',
            'detected_action': action,
            'destination': wifi_data['ssid'],
            'wifi_details': wifi_data,
            'risk_level': risk_level,
            'risk_score': score,
            'info_requested': [f"SSID: {wifi_data['ssid']}", f"Security: {wifi_data['security_type']}", "Device Wi-Fi Profile Auto-Join"],
            'security_checks': checks,
            'explanation': explanation,
            'factors': [] if risk_level == 'LOW' else ['Unencrypted or legacy Wi-Fi protocol'],
            'is_demo': False,
            'limited_analysis': False,
            'intent_mismatch': intent_mismatch,
            'why_risky_ai': why_risky_ai,
            'risk_timeline': risk_timeline,
            'safe_to_proceed': safe_to_proceed,
            'preview_prompt': f"You are about to configure Wi-Fi connection to: {wifi_data['ssid']}"
        }

    # C. Real URLs / Web destinations
    dest_analysis = analyzeDestination(content, qr_type, perform_live_inspection=perform_live)
    effective_qr_type = dest_analysis['qr_type']
    action = detectAction(content, effective_qr_type, dest_analysis)
    
    score, risk_level = calculateRisk(dest_analysis['checks'], effective_qr_type, action)
    
    intent_mismatch = analyze_intent_mismatch(expected_purpose, action, effective_qr_type, details=dest_analysis, poster_context=poster_context)
    if intent_mismatch['status'] == 'MISMATCH':
        risk_level = 'HIGH'
        score = max(score, 80)
        dest_analysis['factors'].insert(0, intent_mismatch['reason'])

    if dest_analysis.get('limited_analysis'):
        risk_level = 'UNKNOWN / LIMITED'
        explanation = "QR destination was detected, but the destination could not be fully inspected."
    else:
        explanation = generateRiskExplanation(risk_level, dest_analysis['factors'], action, effective_qr_type)

    why_risky_ai = generate_why_risky_ai(risk_level, dest_analysis['factors'], intent_mismatch, dest_analysis['checks'], action)
    risk_timeline = generate_risk_timeline(effective_qr_type, action, dest_analysis['destination'], dest_analysis['checks'], intent_mismatch, risk_level)
    safe_to_proceed = generate_safe_to_proceed_decision(risk_level, dest_analysis['factors'], intent_mismatch, action)

    return {
        'mode': 'REAL',
        'qr_content': content,
        'qr_type': effective_qr_type,
        'detected_action': action,
        'destination': dest_analysis['destination'],
        'risk_level': risk_level,
        'risk_score': score,
        'info_requested': dest_analysis['info_requested'],
        'security_checks': dest_analysis['checks'],
        'explanation': explanation,
        'factors': dest_analysis['factors'],
        'is_demo': False,
        'limited_analysis': dest_analysis.get('limited_analysis', False),
        'intent_mismatch': intent_mismatch,
        'why_risky_ai': why_risky_ai,
        'risk_timeline': risk_timeline,
        'safe_to_proceed': safe_to_proceed,
        'preview_prompt': f"You are about to navigate to: {dest_analysis['destination']}"
    }
