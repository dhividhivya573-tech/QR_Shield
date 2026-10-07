import os
import io
import base64
from flask import Flask, render_template, request, jsonify, send_from_directory
import database
import analyzer
import qrcode

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['JSON_SORT_KEYS'] = False

# Ensure database is initialized
database.init_db()

def make_qr_base64(data_str):
    """Generates base64 data URI of a QR code image."""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=2,
        )
        qr.add_data(data_str)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#00f2fe", back_color="#060913")
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
        return f"data:image/png;base64,{img_str}"
    except Exception as e:
        print("QR Generation error:", e)
        return ""

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.get_json() or {}
    demo_id = data.get('demo_id')
    expected_purpose = data.get('expected_purpose')
    poster_context = data.get('poster_context')
    
    if demo_id in (1, 2, 3, 4, 5, 6):
        result = analyzer.get_demo_scenario(int(demo_id))
    else:
        content = data.get('content', '')
        if not content:
            return jsonify({'error': 'No QR code payload provided'}), 400
        is_demo = bool(data.get('is_demo', False))
        result = analyzer.analyze_qr_payload(
            content,
            is_demo_flag=is_demo,
            expected_purpose=expected_purpose,
            poster_context=poster_context
        )
        
    return jsonify(result)

@app.route('/api/analyze-poster', methods=['POST'])
def api_analyze_poster():
    data = request.get_json() or {}
    poster_text = data.get('poster_text', '').strip()
    qr_content = data.get('qr_content', '').strip()
    expected_purpose = data.get('expected_purpose', '').strip()
    
    if not qr_content:
        return jsonify({'error': 'No QR code payload provided for poster analysis'}), 400
        
    result = analyzer.analyze_qr_payload(
        qr_content,
        is_demo_flag=False,
        expected_purpose=expected_purpose or poster_text,
        poster_context=poster_text
    )
    return jsonify(result)

@app.route('/api/history', methods=['GET'])
def api_get_history():
    risk_filter = request.args.get('risk', 'ALL')
    limit = int(request.args.get('limit', 50))
    scans = database.get_scans(risk_filter=risk_filter, limit=limit)
    return jsonify({'scans': scans})

@app.route('/api/history', methods=['POST'])
def api_save_history():
    data = request.get_json() or {}
    if not data:
        return jsonify({'error': 'No scan data provided'}), 400
        
    scan_id = database.insert_scan(data)
    stats = database.get_stats()
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'stats': stats
    })

@app.route('/api/history', methods=['DELETE'])
def api_clear_history():
    database.clear_scans()
    return jsonify({'success': True, 'message': 'Scan history cleared'})

@app.route('/api/stats', methods=['GET'])
def api_get_stats():
    stats = database.get_stats()
    return jsonify(stats)

@app.route('/api/demos', methods=['GET'])
def api_get_demos():
    demos = [
        {
            'id': 1,
            'title': 'Demo Payment QR',
            'type': 'Payment',
            'action': 'Payment',
            'destination': 'abc-pay.example',
            'merchant': 'ABC Store',
            'amount': '₹2,000',
            'risk_level': 'MEDIUM',
            'badge': '🟡 MEDIUM RISK',
            'category': 'standard',
            'summary': 'Payment request of ₹2,000 for ABC Store with domain and redirect warnings.',
            'qr_image': make_qr_base64('upi://pay?pa=abc-store@upi&pn=ABC%20Store&am=2000.00&cu=INR&tn=Invoice%20Order%23901'),
            'scenario': analyzer.get_demo_scenario(1)
        },
        {
            'id': 2,
            'title': 'Demo Registration QR',
            'type': 'Registration Form',
            'action': 'Registration Form',
            'destination': 'registration.example',
            'risk_level': 'MEDIUM',
            'badge': '🟡 MEDIUM RISK',
            'category': 'standard',
            'summary': 'Registration form requesting personal information (Name, Email, Phone, College ID).',
            'qr_image': make_qr_base64('https://registration.example/hackathon-signup'),
            'scenario': analyzer.get_demo_scenario(2)
        },
        {
            'id': 3,
            'title': 'Demo Suspicious Login QR',
            'type': 'Login',
            'action': 'Login',
            'destination': 'secure-login.example',
            'risk_level': 'HIGH',
            'badge': '🔴 HIGH RISK',
            'category': 'standard',
            'summary': 'Phishing destination requesting login credentials with domain and redirect anomalies.',
            'qr_image': make_qr_base64('https://secure-login.example/signin?redirect=session_update'),
            'scenario': analyzer.get_demo_scenario(3)
        },
        {
            'id': 4,
            'title': 'Event Registration → Login + Password mismatch',
            'type': 'Login',
            'action': 'Login',
            'destination': 'secure-login.example',
            'risk_level': 'HIGH',
            'badge': '🔴 INTENT MISMATCH',
            'category': 'mismatch',
            'summary': 'Poster claims Free Event Registration, but the QR points to a credential harvesting login portal.',
            'qr_image': make_qr_base64('https://secure-login.example/auth?event=hackathon2026'),
            'scenario': analyzer.get_demo_scenario(4)
        },
        {
            'id': 5,
            'title': 'Payment ₹50 → QR requests ₹500 mismatch',
            'type': 'Payment',
            'action': 'Payment',
            'destination': 'canteen-counter@upi',
            'merchant': 'Cafeteria Store',
            'amount': '₹500.00',
            'risk_level': 'HIGH',
            'badge': '🔴 FINANCIAL MISMATCH',
            'category': 'mismatch',
            'summary': 'Poster states ₹50 Meal Combo, but the encoded UPI payload requests an unauthorized ₹500.',
            'qr_image': make_qr_base64('upi://pay?pa=canteen-counter@upi&pn=Cafeteria%20Store&am=500.00&cu=INR&tn=Lunch%20Meal%20Combo'),
            'scenario': analyzer.get_demo_scenario(5)
        },
        {
            'id': 6,
            'title': 'Safe Website → Intent Matched',
            'type': 'Website',
            'action': 'Website',
            'destination': 'https://example.com',
            'risk_level': 'LOW',
            'badge': '🟢 INTENT MATCHED',
            'category': 'matched',
            'summary': 'User expects official documentation portal and destination matches transparently with active TLS.',
            'qr_image': make_qr_base64('https://example.com/hackathon-rules'),
            'scenario': analyzer.get_demo_scenario(6)
        }
    ]
    return jsonify({'demos': demos})

@app.route('/api/generate-qr', methods=['POST'])
def api_generate_qr():
    data = request.get_json() or {}
    text = data.get('text', '')
    if not text:
        return jsonify({'error': 'No text provided'}), 400
    img_uri = make_qr_base64(text)
    return jsonify({'qr_image': img_uri, 'text': text})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"[*] Starting QR Shield Security Engine on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=True)
