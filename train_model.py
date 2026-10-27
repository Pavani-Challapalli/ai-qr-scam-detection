import os
import re
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Configuration & Lists for Feature Extraction
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "banking", "paypal", "chase", "netflix",
    "account", "signin", "wallet", "crypto", "free", "gift", "claim", "prize",
    "invoice", "support", "card", "refund", "billing", "re-activate", "confirm"
]

HIGH_RISK_TLDS = [
    "xyz", "top", "tk", "ml", "cf", "gq", "link", "zip", "download", "loan", 
    "click", "work", "date", "men", "party", "gdn", "bid", "info", "tech"
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rebrand.ly", "is.gd", "buff.ly", 
    "adf.ly", "ow.ly", "git.io", "lnkd.in", "t.me"
]

KNOWN_BRANDS = [
    "paypal", "chase", "netflix", "google", "microsoft", "amazon", "apple", 
    "facebook", "instagram", "twitter", "bankofamerica", "wellsfargo", "binance", "coinbase"
]

OFFICIAL_DOMAINS = {
    "paypal": "paypal.com",
    "chase": "chase.com",
    "netflix": "netflix.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com"
}

def extract_features(url):
    """
    Extract numerical and boolean features from a URL for machine learning classification.
    """
    url_lower = url.lower()
    
    # 1. Basic length and structural counts
    url_length = len(url)
    num_dots = url_lower.count('.')
    num_hyphens = url_lower.count('-')
    num_slashes = url_lower.count('/')
    
    # 2. IP Address check (often used in malicious domains to bypass DNS reputation)
    has_ip = 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url_lower) else 0
    
    # 3. Presence of '@' (used for credentials obfuscation)
    has_at = 1 if '@' in url_lower else 0
    
    # 4. URL Shortener check
    is_shortened = 0
    for shortener in SHORTENER_DOMAINS:
        if shortener in url_lower:
            is_shortened = 1
            break
            
    # 5. Extract domain and check elements
    # Remove protocol prefix to scan hostname
    clean_host = url_lower
    if "://" in clean_host:
        clean_host = clean_host.split("://", 1)[1]
    if "/" in clean_host:
        clean_host = clean_host.split("/", 1)[0]
        
    subdomain_count = max(0, clean_host.count('.') - 1)
    
    # High risk TLD check
    is_tld_threat = 0
    tld_match = clean_host.split('.')[-1] if '.' in clean_host else ""
    if tld_match in HIGH_RISK_TLDS:
        is_tld_threat = 1
        
    # 6. Keyword matching (scam phrases)
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    
    # 7. Brand spoofing / Typosquatting check
    # Check if a popular brand keyword is in the URL, but it is NOT the official domain name.
    # For example, "paypal-update-alert.xyz" contains "paypal" but is not "paypal.com"
    brand_spoof = 0
    for brand in KNOWN_BRANDS:
        if brand in url_lower:
            official = OFFICIAL_DOMAINS[brand]
            if official not in clean_host:
                brand_spoof = 1
                break
                
    # 8. Numeric ratio (phishing sites often have heavy digit strings)
    digits = sum(1 for c in url_lower if c.isdigit())
    digit_ratio = digits / url_length if url_length > 0 else 0
    
    return [
        url_length,
        num_dots,
        num_hyphens,
        num_slashes,
        has_ip,
        has_at,
        is_shortened,
        subdomain_count,
        is_tld_threat,
        keyword_count,
        brand_spoof,
        digit_ratio
    ]

# Feature columns list
FEATURE_NAMES = [
    "url_length", "num_dots", "num_hyphens", "num_slashes", "has_ip", "has_at", 
    "is_shortened", "subdomain_count", "is_tld_threat", "keyword_count", "brand_spoof", "digit_ratio"
]

def generate_synthetic_dataset():
    """
    Generate a balanced, high-quality synthetic URL dataset to train the model.
    Labels: 0 = Safe, 1 = Suspicious, 2 = Fraud
    """
    data = []
    
    # --- Category 0: Safe URLs ---
    safe_templates = [
        "https://www.google.com",
        "https://en.wikipedia.org/wiki/Main_Page",
        "https://github.com/trending",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://www.nytimes.com/section/technology",
        "https://www.paypal.com/signin",
        "https://www.netflix.com/browse",
        "https://www.chase.com/personal/banking",
        "https://apple.com/iphone-15",
        "https://www.microsoft.com/en-us/store",
        "https://stackoverflow.com/questions/tagged/python",
        "https://news.ycombinator.com",
        "https://medium.com",
        "https://spotify.com",
        "https://zoom.us",
        "https://www.wellsfargo.com",
        "https://www.bankofamerica.com/online-banking",
        "https://www.coinbase.com/dashboard",
        "https://www.binance.com/en",
        "https://www.facebook.com/messages",
        "https://instagram.com/p/B9h5k",
        "https://twitter.com/home"
    ]
    # Add variations of safe paths to reach 400 samples
    for i in range(400):
        base = safe_templates[i % len(safe_templates)]
        path_num = i * 17
        random_paths = [
            f"{base}/page-{path_num}",
            f"{base}/resource/item-{path_num}",
            f"{base}/search?q=query-{path_num}&category=web",
            f"{base}/about/careers/jobs?id={path_num}",
            f"{base}/settings/profile/security?mode=view",
            f"{base}"
        ]
        url = random_paths[i % len(random_paths)]
        data.append((url, 0)) # Safe

    # --- Category 1: Suspicious URLs ---
    # Shorteners, slightly long, or matching high-risk TLDs but without explicit brand hijacking
    suspicious_templates = [
        "https://bit.ly/3kX9sPq",
        "https://tinyurl.com/y6u89j",
        "http://t.co/9aK81lq",
        "https://rebrand.ly/link-9941",
        "http://my-blog-portal.xyz/post-1002",
        "https://download-free-games.top/installer.zip",
        "http://click-here-bonus.link/offer",
        "https://secure-node-connection.tech/api",
        "http://invoice-ledger.info/view",
        "https://quick-support.work/helpdesk",
        "https://date-tonight.party/signup",
        "http://finance-charts.tech/analytics",
        "https://crypto-market-cap.xyz",
        "https://safe-wallet-connection.xyz/keys",
        "http://verify-identity.link/portal",
        "https://web-cloud-backup.download/files",
        "https://free-movie-streaming.online/watch"
    ]
    for i in range(400):
        base = suspicious_templates[i % len(suspicious_templates)]
        salt = i * 29
        random_paths = [
            f"{base}?id={salt}",
            f"{base}/get-file?ref={salt}",
            f"{base}/redirect/auth-{salt}",
            f"{base}/secure-gate-{salt}",
            f"{base}"
        ]
        url = random_paths[i % len(random_paths)]
        data.append((url, 1)) # Suspicious

    # --- Category 2: Fraud URLs ---
    # IP addresses, brand typosquatting, credential obscuring, urgent keywords
    fraud_templates = [
        "http://192.168.1.105/paypal.com/signin",
        "https://103.22.45.109/chase/login",
        "https://paypa1-security-alert.xyz/verify",
        "http://nettfl1x-billing-update.top/account",
        "https://chase-bank-verify-identity.com/secure",
        "http://support-amazon-refund.link/claim",
        "http://verification-paypal-update.xyz/signin",
        "https://bankofamerica-secure-login.xyz/accounts",
        "https://wellsfargo-security-check.top/portal",
        "https://binance-wallet-support.link/kyc",
        "https://coinbase-auth-verify.xyz/signin",
        "http://free-giftcard-claim.top/win-prize",
        "http://user:pass@192.168.4.1/auth/login",
        "https://paypaI-billing-issue.com/secure-login", # Capital I instead of l
        "https://microsoft-office365-upgrade.xyz/login",
        "http://chase-security-verify-customer-support.xyz/account/login",
        "https://appleid-verification-icloud-secure.top/manage"
    ]
    for i in range(400):
        base = fraud_templates[i % len(fraud_templates)]
        salt = i * 43
        random_paths = [
            f"{base}?session={salt}&auth=true",
            f"{base}/login.php?ref=security_{salt}",
            f"{base}/invoice/claim-prize-id-{salt}",
            f"{base}/refund-form-secure-{salt}",
            f"{base}"
        ]
        url = random_paths[i % len(random_paths)]
        data.append((url, 2)) # Fraud
        
    return data

def main():
    print("--------------------------------------------------")
    print("   AI-Based QR Code Scam Detection System         ")
    print("         Model Training & Generation              ")
    print("--------------------------------------------------")
    
    print("1. Generating synthetic, balanced URL dataset...")
    raw_data = generate_synthetic_dataset()
    print(f"   Generated {len(raw_data)} URL samples.")
    
    # 2. Extract features
    print("2. Extracting numerical and structural features from URLs...")
    features_list = []
    labels_list = []
    
    for url, label in raw_data:
        feats = extract_features(url)
        features_list.append(feats)
        labels_list.append(label)
        
    X = np.array(features_list)
    y = np.array(labels_list)
    
    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df['Label'] = y
    
    # Print label distribution
    print("\n   Dataset Label Distribution:")
    print("   0 (Safe)      :", np.sum(y == 0))
    print("   1 (Suspicious):", np.sum(y == 1))
    print("   2 (Fraud)     :", np.sum(y == 2))
    
    # 3. Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # 4. Train Random Forest Classifier
    print("\n3. Training Scikit-Learn Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    model.fit(X_train, y_train)
    
    # 5. Evaluate Model
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"   Model Accuracy: {acc:.4f} ({acc*100:.2f}%)")
    
    print("\n   Detailed Classification Report:")
    target_names = ['Safe', 'Suspicious', 'Fraud']
    print(classification_report(y_test, y_pred, target_names=target_names))
    
    # Print Feature Importances
    print("   Feature Importances:")
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    for idx in indices:
        print(f"     - {FEATURE_NAMES[idx]:<18}: {importances[idx]:.4f}")
        
    # 6. Save model and metadata
    model_path = "scam_detector_model.pkl"
    print(f"\n4. Serializing model and metadata to {model_path}...")
    
    model_metadata = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "suspicious_keywords": SUSPICIOUS_KEYWORDS,
        "high_risk_tlds": HIGH_RISK_TLDS,
        "shortener_domains": SHORTENER_DOMAINS,
        "known_brands": KNOWN_BRANDS,
        "official_domains": OFFICIAL_DOMAINS
    }
    
    joblib.dump(model_metadata, model_path)
    print("   Model training and serialization completed successfully!")
    print("--------------------------------------------------")

if __name__ == "__main__":
    main()
