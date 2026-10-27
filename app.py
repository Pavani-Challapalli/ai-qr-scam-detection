import os
import re
import base64
import numpy as np
import cv2
import joblib
from flask import Flask, request, jsonify, render_template

app = Flask(__name__, template_folder='templates', static_folder='static')

# Load the trained Scikit-Learn Model and metadata
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scam_detector_model.pkl")
model_data = None
model = None

if os.path.exists(MODEL_PATH):
    try:
        model_data = joblib.load(MODEL_PATH)
        model = model_data["model"]
        print("[INIT] Successfully loaded Scikit-Learn model.")
    except Exception as e:
        print(f"[ERROR] Failed to load model: {e}")
else:
    print("[WARNING] Model file not found. Please run 'train_model.py' to generate 'scam_detector_model.pkl' first!")

# Retrieve configurations from serialized metadata, with fallbacks
SUSPICIOUS_KEYWORDS = model_data["suspicious_keywords"] if model_data else [
    "login", "verify", "secure", "update", "banking", "paypal", "chase", "netflix",
    "account", "signin", "wallet", "crypto", "free", "gift", "claim", "prize",
    "invoice", "support", "card", "refund", "billing"
]
HIGH_RISK_TLDS = model_data["high_risk_tlds"] if model_data else [
    "xyz", "top", "tk", "ml", "cf", "gq", "link", "zip", "download", "loan", "click"
]
SHORTENER_DOMAINS = model_data["shortener_domains"] if model_data else [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rebrand.ly", "is.gd"
]
KNOWN_BRANDS = model_data["known_brands"] if model_data else ["paypal", "chase", "netflix", "google", "amazon"]
OFFICIAL_DOMAINS = model_data["official_domains"] if model_data else {"paypal": "paypal.com", "chase": "chase.com"}

def extract_features(url):
    """
    Extract identical numerical/structural features as trained in train_model.py.
    """
    url_lower = url.lower()
    url_length = len(url)
    num_dots = url_lower.count('.')
    num_hyphens = url_lower.count('-')
    num_slashes = url_lower.count('/')
    
    has_ip = 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url_lower) else 0
    has_at = 1 if '@' in url_lower else 0
    
    is_shortened = 0
    for shortener in SHORTENER_DOMAINS:
        if shortener in url_lower:
            is_shortened = 1
            break
            
    clean_host = url_lower
    if "://" in clean_host:
        clean_host = clean_host.split("://", 1)[1]
    if "/" in clean_host:
        clean_host = clean_host.split("/", 1)[0]
        
    subdomain_count = max(0, clean_host.count('.') - 1)
    
    is_tld_threat = 0
    tld_match = clean_host.split('.')[-1] if '.' in clean_host else ""
    if tld_match in HIGH_RISK_TLDS:
        is_tld_threat = 1
        
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    
    brand_spoof = 0
    for brand in KNOWN_BRANDS:
        if brand in url_lower:
            official = OFFICIAL_DOMAINS.get(brand, f"{brand}.com")
            if official not in clean_host:
                brand_spoof = 1
                break
                
    digits = sum(1 for c in url_lower if c.isdigit())
    digit_ratio = digits / url_length if url_length > 0 else 0
    
    return [
        url_length, num_dots, num_hyphens, num_slashes, has_ip, has_at,
        is_shortened, subdomain_count, is_tld_threat, keyword_count, brand_spoof, digit_ratio
    ]

def analyze_payload_heuristics(url):
    """
    Perform a granular security checklist scan on the URL/payload to supply detailed UI reports.
    """
    url_lower = url.lower()
    
    # Remove protocol prefix to scan hostname
    clean_host = url_lower
    if "://" in clean_host:
        clean_host = clean_host.split("://", 1)[1]
    if "/" in clean_host:
        clean_host = clean_host.split("/", 1)[0]
        
    tld_match = clean_host.split('.')[-1] if '.' in clean_host else ""
    
    heuristics = []
    
    # 1. Check if it's a URL or plain text
    is_url = url_lower.startswith(("http://", "https://", "www.")) or ('.' in clean_host and len(clean_host) > 4)
    
    if not is_url:
        heuristics.append({
            "check": "Protocol and URL Format Check",
            "status": "PASSED",
            "message": "QR content is treated as secure plain-text, not a web link.",
            "risk": "low"
        })
        return heuristics, 10
        
    # 2. Check for URL Shorteners
    shortened = any(sh in url_lower for sh in SHORTENER_DOMAINS)
    heuristics.append({
        "check": "URL Redirection & Shorteners Check",
        "status": "FAILED" if shortened else "PASSED",
        "message": "Uses obscure URL shortener redirection service." if shortened else "Direct domain destination detected.",
        "risk": "medium" if shortened else "low"
    })
    
    # 3. Check for IP Address
    has_ip = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url_lower)
    heuristics.append({
        "check": "IP Hostname Masking Check",
        "status": "FAILED" if has_ip else "PASSED",
        "message": f"Uses direct IP Hostname ({has_ip.group() if has_ip else ''}) masking true identity." if has_ip else "Uses named domain hostname registration.",
        "risk": "high" if has_ip else "low"
    })
    
    # 4. Check for Suspicious TLD
    tld_threat = tld_match in HIGH_RISK_TLDS
    heuristics.append({
        "check": "Top-Level Domain (TLD) Safety Check",
        "status": "FAILED" if tld_threat else "PASSED",
        "message": f"Uses high-risk TLD '.{tld_match}' commonly associated with spam registrations." if tld_threat else f"Uses trusted top-level domain '.{tld_match}'.",
        "risk": "high" if tld_threat else "low"
    })
    
    # 5. Check for Obfuscated Credentials
    has_at = '@' in url_lower
    heuristics.append({
        "check": "Credential Obfuscation (@) Check",
        "status": "FAILED" if has_at else "PASSED",
        "message": "Contains '@' symbol designed to hide the malicious domain.",
        "risk": "high" if has_at else "low"
    })
    
    # 6. Check for Brand Spoofing / Typosquatting
    brand_spoof = False
    spoofed_brand = ""
    for brand in KNOWN_BRANDS:
        if brand in url_lower:
            official = OFFICIAL_DOMAINS.get(brand, f"{brand}.com")
            if official not in clean_host:
                brand_spoof = True
                spoofed_brand = brand
                break
                
    heuristics.append({
        "check": "Brand Integrity & Spoofing Scan",
        "status": "FAILED" if brand_spoof else "PASSED",
        "message": f"Spoof Warning: Mentions brand '{spoofed_brand.upper()}' but redirects to an unofficial server." if brand_spoof else "No famous brand imitation detected.",
        "risk": "high" if brand_spoof else "low"
    })
    
    # 7. Check for Phishing Keywords
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    keyword_failed = len(matched_keywords) > 0
    heuristics.append({
        "check": "Social Engineering Keyword Scan",
        "status": "FAILED" if keyword_failed else "PASSED",
        "message": f"Contains social engineering keywords: {', '.join(matched_keywords[:3])}" if keyword_failed else "No aggressive social engineering keywords identified.",
        "risk": "medium" if keyword_failed else "low"
    })
    
    # Calculate custom threat score
    threat_points = 0
    if shortened: threat_points += 20
    if has_ip: threat_points += 30
    if tld_threat: threat_points += 25
    if has_at: threat_points += 25
    if brand_spoof: threat_points += 40
    if keyword_failed: threat_points += min(30, len(matched_keywords) * 10)
    
    threat_score = min(100, max(5, threat_points))
    
    return heuristics, threat_score

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_qr_text():
    """
    Accepts pre-decoded QR text (from client-side jsQR) and runs
    AI classification + heuristics without needing to process an image.
    Used by the live webcam scanning path.
    """
    try:
        global model
        if model is None:
            return jsonify({"success": False, "error": "AI model offline. Run train_model.py first."}), 500

        data = request.get_json()
        if not data or 'qr_data' not in data:
            return jsonify({"success": False, "error": "No QR data provided."}), 400

        qr_data = data['qr_data'].strip()
        if not qr_data:
            return jsonify({"success": False, "error": "Empty QR payload received."}), 400

        # Feature extraction
        features = extract_features(qr_data)

        # AI classification
        prediction = model.predict([features])[0]
        probabilities = model.predict_proba([features])[0]

        classification_mapping = {0: "Safe", 1: "Suspicious", 2: "Fraud"}
        classification = classification_mapping[prediction]
        confidence = float(probabilities[prediction]) * 100

        # Detailed heuristics report
        heuristics, base_threat_score = analyze_payload_heuristics(qr_data)

        if classification == "Safe":
            threat_score = min(25, int(base_threat_score * 0.5))
        elif classification == "Suspicious":
            threat_score = max(30, min(65, int(base_threat_score)))
        else:
            threat_score = max(70, min(100, int(base_threat_score * 1.2)))

        return jsonify({
            "success": True,
            "qr_detected": True,
            "qr_data": qr_data,
            "classification": classification,
            "confidence": round(confidence, 1),
            "threat_score": threat_score,
            "features_extracted": {
                "length": features[0],
                "dots": features[1],
                "hyphens": features[2],
                "has_ip": bool(features[4]),
                "is_shortened": bool(features[6]),
                "subdomains": features[7],
                "is_tld_threat": bool(features[8]),
                "keyword_count": features[9],
                "brand_spoof": bool(features[10])
            },
            "heuristics": heuristics
        })

    except Exception as e:
        return jsonify({"success": False, "error": f"Analysis error: {str(e)}"}), 500


@app.route('/scan', methods=['POST'])
def scan_qr():
    try:
        # Check model loaded
        global model
        if model is None:
            # Try reloading model in case they just trained it
            if os.path.exists(MODEL_PATH):
                try:
                    global model_data
                    model_data = joblib.load(MODEL_PATH)
                    model = model_data["model"]
                except Exception as ex:
                    return jsonify({
                        "success": False, 
                        "error": "Model initialization failed on backend. Please ensure train_model.py was executed."
                    }), 500
            else:
                return jsonify({
                    "success": False, 
                    "error": "Scam classification model is currently offline. Run 'python train_model.py' to launch it!"
                }), 500

        data = request.get_json()
        if not data or 'image' not in data:
            return jsonify({"success": False, "error": "No image payload found."}), 400
            
        # Parse Base64 Image
        image_data = data['image']
        if ',' in image_data:
            image_data = image_data.split(',', 1)[1]
            
        img_bytes = base64.b64decode(image_data)
        np_arr = np.frombuffer(img_bytes, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        
        if img is None:
            return jsonify({"success": False, "error": "Failed to parse image bytes."}), 400
            
        # 1. OpenCV QR Code Scanning Engine
        qr_detector = cv2.QRCodeDetector()
        qr_data, bbox, rectified_image = qr_detector.detectAndDecode(img)
        
        # Fallback to secondary search parameters if first pass failed
        if not qr_data and bbox is not None:
            # Sometimes QR is detected but not decoded, try grayscale or upscaling
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            qr_data, _, _ = qr_detector.detectAndDecode(gray)
            
        if not qr_data:
            return jsonify({"success": False, "qr_detected": False, "error": "No QR Code detected in the viewport. Position the code clearly."})
            
        # 2. Extract Features
        features = extract_features(qr_data)
        
        # 3. Model Classification Predict
        prediction = model.predict([features])[0] # 0 = Safe, 1 = Suspicious, 2 = Fraud
        probabilities = model.predict_proba([features])[0]
        
        classification_mapping = {0: "Safe", 1: "Suspicious", 2: "Fraud"}
        classification = classification_mapping[prediction]
        confidence = float(probabilities[prediction]) * 100
        
        # 4. Generate Heuristic Detailed Logs & Threat Score
        heuristics, base_threat_score = analyze_payload_heuristics(qr_data)
        
        # Align Scikit-learn prediction and threat score
        if classification == "Safe":
            threat_score = min(25, int(base_threat_score * 0.5))
        elif classification == "Suspicious":
            threat_score = max(30, min(65, int(base_threat_score)))
        else: # Fraud
            threat_score = max(70, min(100, int(base_threat_score * 1.2)))
            
        return jsonify({
            "success": True,
            "qr_detected": True,
            "qr_data": qr_data,
            "classification": classification,
            "confidence": round(confidence, 1),
            "threat_score": threat_score,
            "features_extracted": {
                "length": features[0],
                "dots": features[1],
                "hyphens": features[2],
                "has_ip": bool(features[4]),
                "is_shortened": bool(features[6]),
                "subdomains": features[7],
                "is_tld_threat": bool(features[8]),
                "keyword_count": features[9],
                "brand_spoof": bool(features[10])
            },
            "heuristics": heuristics
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": f"Internal scan error: {str(e)}"}), 500

if __name__ == '__main__':
    # Default Flask runs on port 5001 to avoid Windows port conflicts
    app.run(debug=True, host='127.0.0.1', port=5001)
